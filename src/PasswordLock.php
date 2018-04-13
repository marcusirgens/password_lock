<?php
declare(strict_types=1);
namespace ParagonIE\PasswordLock;

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;
use \ParagonIE\ConstantTime\Base64;
use \ParagonIE\ConstantTime\Binary;

class PasswordLock
{
    private const SHA384 = 0;
    private const SHA3_384 = 1;
    private const SHA256 = 2;
    
    /**
     * Chooses the best available hashing algorithm for hashing the password.
     * Note that this is the _prehash_ which is done before base64 and
     * password_hash.
     *
     * @access private
     * @static
     * @return int The constant representing the different algorithms for
     *             hash()
     * @throws \Exception
     */
    private static function chooseHashAlgo()
    {
        if (in_array("sha3-384", $algos = hash_algos())) {
            return static::SHA3_384;
        } elseif (in_array("sha384", $algos)) {
            return static::SHA384;
        } elseif (in_array("sha256", $algos)) {
            return static::SHA256;
        } else {
            throw new \Exception("No valid hash algos found.");
        }
    }
    
    /**
     * Hashes a password.
     *
     * @param int $algo
     * @param string $password
     * @access private
     * @static
     * @return string
     * @throws \Exception
     */
    private static function hash(int $algo, string $password): string
    {
        switch ($algo) {
            case static::SHA384:
                return \hash('sha384', $password, true);
            case static::SHA3_384:
                return \hash('sha3-384', $password, true);
            case static::SHA256:
                return \hash('sha256', $password, true);
            default:
                throw new \Exception("No valid hash algos for hash() found.");
        }
    }
    
    /**
     * Chooses the best available hashing algorithm for hashing the password.
     *
     * @access private
     * @static
     * @return int The constant representing the different algorithms for
     *             password_hash()
     * @throws \Exception
     */
    private static function choosePasswordHashAlgo()
    {
        if (defined("PASSWORD_ARGON2I")) {
            return \PASSWORD_ARGON2I;
        } elseif (defined("PASSWORD_DEFAULT")) {
            return \PASSWORD_DEFAULT;
        } else {
            throw new \Exception("No valid hash algos for password_hash() found.");
        }
    }
    
    /**
     * Chooses the best available hashing algorithm for hashing the password.
     *
     * @access private
     * @static
     * @param string $string The hash, with or without the hash() algo prefix.
     * @return array[string] The constant representing the algorithm used for
     *                       hash() and the password hash string.
     */
    private static function getAlgoAndHash(string $string): array
    {
        if (strpos($string, "%") === 0) {
            $algo = intval(substr($string, 1, 1));
            $hash = substr($string, 2);
        } else {
            // This is the one used in the implementation prior to the update
            // where sha3-384 was implemented, so if no algo is chosen, use
            // sha384
            $algo = static::SHA384;
            $hash = $string;
        }
        
        return [$algo, $hash];
    }
    
    /**
     * 1. Hash password using bcrypt-base64-prehash
     * 2. Encrypt-then-MAC the hash
     *
     * @param string $password
     * @param Key $aesKey
     * @param int $passwordAlgo (default: null) PASSWORD_DEFAULT /
     *                          PASSWORD_ARGON2I
     * @param ?array $options (default: null) Options passed to the
     *                        password_hash function
     * @return string
     * @throws \Exception
     * @throws \InvalidArgumentException
     */
    public static function hashAndEncrypt(
        string $password,
        Key $aesKey,
        ?int $passwordAlgo = null,
        ?array $options = null
    ): string {
        /** @var int $algo */
        $algo = static::chooseHashAlgo();
        
        /** @var string $hash */
        $hash = \password_hash(
            Base64::encode(
                static::hash($algo, $password)
            ),
            $passwordAlgo ?? static::choosePasswordHashAlgo(),
            $options ?? []
        );
        if (!\is_string($hash)) {
            throw new \Exception("Unknown hashing error.");
        }
        
        return Crypto::encrypt("%" . $algo . $hash, $aesKey);
    }
    
    /**
     * 1. VerifyHMAC-then-Decrypt the ciphertext to get the hash
     * 2. Verify that the password matches the hash
     *
     * @param string $password
     * @param string $ciphertext
     * @param string $aesKey - must be exactly 16 bytes
     * @return bool
     * @throws \Exception
     * @throws \InvalidArgumentException
     */
    public static function decryptAndVerifyLegacy(string $password, string $ciphertext, string $aesKey): bool
    {
        if (Binary::safeStrlen($aesKey) !== 16) {
            throw new \Exception("Encryption keys must be 16 bytes long");
        }
        $hash = Crypto::legacyDecrypt(
            $ciphertext,
            $aesKey
        );
        if (!\is_string($hash)) {
            throw new \Exception("Unknown hashing error.");
        }
        return \password_verify(
            Base64::encode(
                \hash('sha256', $password, true)
            ),
            $hash
        );
    }

    /**
     * 1. VerifyHMAC-then-Decrypt the ciphertext to get the prehash algo and
     *    the hash
     * 2. Verify that the password matches the hash
     *
     * @param string $password
     * @param string $ciphertext
     * @param Key $aesKey
     * @return bool
     * @throws \Exception
     * @throws \InvalidArgumentException
     */
    public static function decryptAndVerify(string $password, string $ciphertext, Key $aesKey): bool
    {
        $decrypted = Crypto::decrypt(
            $ciphertext,
            $aesKey
        );
        
        list($algo, $hash) = static::getAlgoAndHash($decrypted);
                
        if (!\is_string($hash)) {
            throw new \Exception("Unknown hashing error.");
        }
        return \password_verify(
            Base64::encode(
                static::hash($algo, $password)
            ),
            $hash
        );
    }
    
    /**
     * 1. VerifyHMAC-then-Decrypt the ciphertext to get the hash
     * 2. Check if the prehash algo has changed
     * 3. Check if the password_hash algo has changed
     * 4. If 2 or 3, return true, else return false
     *
     * @param string $ciphertext
     * @param Key $aesKey
     * @param int $passwordAlgo (default: null) PASSWORD_DEFAULT /
     *                          PASSWORD_ARGON2I
     * @param ?array $options (default: null) Options passed to the
     *                        password_hash function
     * @return string
     * @throws \Exception
     * @throws \InvalidArgumentException
     */
    public static function decryptAndCheckIfNeedsRehash(
        string $ciphertext,
        Key $aesKey,
        ?int $passwordAlgo = null,
        ?array $options = null
    ): bool {
        $decrypted = Crypto::decrypt(
            $ciphertext,
            $aesKey
        );
        
        list($algo, $hash) = static::getAlgoAndHash($decrypted);
        
        if (!\is_string($hash)) {
            throw new \Exception("Unknown hashing error.");
        }
        
        if ($algo !== static::chooseHashAlgo()) {
            return true;
        }
        
        if (\password_needs_rehash(
            $hash,
            $passwordAlgo ?? static::choosePasswordHashAlgo(),
            $options ?? []
        )) {
            return true;
        }
        
        return false;
    }

    /**
     * Key rotation method -- decrypt with your old key then re-encrypt with your new key
     *
     * @param string $ciphertext
     * @param  Key $oldKey
     * @param Key $newKey
     * @return string
     */
    public static function rotateKey(string $ciphertext, Key $oldKey, Key $newKey): string
    {
        $plaintext = Crypto::decrypt($ciphertext, $oldKey);
        return Crypto::encrypt($plaintext, $newKey);
    }

    /**
     * For migrating from an older version of the library
     *
     * @param string $password
     * @param string $ciphertext
     * @param string $oldKey
     * @param Key $newKey
     * @return string
     * @throws \Exception
     */
    public static function upgradeFromVersion1(
        string $password,
        string $ciphertext,
        string $oldKey,
        Key $newKey
    ): string {
        if (!self::decryptAndVerifyLegacy($password, $ciphertext, $oldKey)) {
            throw new \Exception(
                'The correct password is necessary for legacy migration.'
            );
        }
        $plaintext = Crypto::legacyDecrypt($ciphertext, $oldKey);
        return self::hashAndEncrypt($plaintext, $newKey);
    }
}
