<?php
declare(strict_types=1);
namespace ParagonIE\PasswordLock;

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;
use \ParagonIE\ConstantTime\Base64;
use \ParagonIE\ConstantTime\Binary;

class PasswordLock
{
    private const HASH_ALGO_NONE = 0;
    private const HASH_ALGO_SHA256 = 1;
    private const HASH_ALGO_SHA384 = 2;
    private const HASH_ALGO_SHA3_384 = 3;
    
    /**
     * Return info about the hash
     *
     * @param string $hash
     * @return array The hash, the preHashAlgo and the passwordAlgo
     */
    private static function getPasswordInfo(string $hash): array
    {
        if (strpos($hash, "%") === 0) {
            $hashAlgo = intval(substr($hash, 1, 1));
            $hash = substr($hash, 2);
        } else {
            // This is the default
            $hashAlgo = static::HASH_ALGO_SHA384;
        }
        
        $passwordAlgo = password_get_info($hash)['algo'];
        
        return [
            'hash' => $hash,
            'preHashAlgo' => $hashAlgo,
            'passwordAlgo' => $passwordAlgo,
        ];
    }
    
    /**
     * Determines which hash algo to use for prehashing (if any)
     *
     * @param int $passwordAlgo
     * @return int
     * @throws \Exception
     */
    private static function getBestPreHashAlgo(int $passwordAlgo): int
    {
        if ($passwordAlgo == \PASSWORD_ARGON2I) {
            return static::HASH_ALGO_NONE;
        } elseif (in_array("sha3-384", ($algos = hash_algos()))) {
            return static::HASH_ALGO_SHA3_384;
        } elseif (in_array("sha384", $algos)) {
            return static::HASH_ALGO_SHA384;
        } elseif (in_array("sha256", $algos)) {
            return static::HASH_ALGO_SHA256;
        } else {
            throw new \Exception("No suitable hash algos found");
        }
    }
    
    /**
     * Determines which algo to use for password hashing
     *
     * @return int
     * @throws \Exception
     */
    private static function getBestPasswordHashAlgo(): int
    {
        if (defined("PASSWORD_ARGON2I")) {
            return \PASSWORD_ARGON2I;
        } elseif (defined("PASSWORD_BCRYPT")) {
            return \PASSWORD_BCRYPT;
        }
    }
    
    /**
     * Wrapper for the Base64-SHA prehashing to avoid truncating with bcrypt
     *
     * @param string $password
     * @param int $preHashAlgo
     * @return string
     */
    private static function preHashPassword(string $password, int $preHashAlgo): string
    {
        switch ($preHashAlgo) {
            case static::HASH_ALGO_NONE:
                return $password;
                break;
            case static::HASH_ALGO_SHA256:
                return Base64::encode(\hash('sha256', $password, true));
                break;
            case static::HASH_ALGO_SHA3_384:
                return Base64::encode(\hash('sha3-384', $password, true));
                break;
            case static::HASH_ALGO_SHA384:
            default:
                return Base64::encode(\hash('sha384', $password, true));
                break;
        }
    }
    
    /**
     * Wrapper for the password_hash function
     *
     * @param string $password
     * @param int $preHashAlgo
     * @param int $passwordAlgo
     * @param array $passwordOptions
     * @return string
     */
    private static function hashPassword(
        string $password,
        int $preHashAlgo,
        int $passwordAlgo,
        array $passwordOptions
    ): string {
        $preHashed = static::preHashPassword($password, $preHashAlgo);
        return '%' . $preHashAlgo . \password_hash($preHashed, $passwordAlgo, $passwordOptions);
    }

    /**
     * 1. Hash password using bcrypt-base64-SHA2/3 or argon2i
     * 2. Encrypt-then-MAC the hash
     *
     * @param string $password
     * @param Key $aesKey
     * @param ?int $passwordAlgo (default: null)
     * @param array $passwordOptions (default: [])
     * @return string
     * @throws \Exception
     * @throws \InvalidArgumentException
     */
    public static function hashAndEncrypt(
        string $password,
        Key $aesKey,
        ?int $passwordAlgo = null,
        array $passwordOptions = []
    ): string {
        
        $passwordAlgo = $passwordAlgo ?? static::getBestPasswordHashAlgo();
        $preHashAlgo = static::getBestPreHashAlgo($passwordAlgo);

        $hashedPassword = static::hashPassword(
            $password,
            $preHashAlgo,
            $passwordAlgo,
            $passwordOptions
        );
        
        if (!\is_string($hashedPassword)) {
            throw new \Exception("Unknown hashing error.");
        }
        return Crypto::encrypt($hashedPassword, $aesKey);
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
                
        list($hash, $preHashAlgo, $passwordAlgo) = array_values(static::getPasswordInfo($hash));
                
        if (!\is_string($hash)) {
            throw new \Exception("Unknown hashing error.");
        }
        return \password_verify(
            static::preHashPassword($password, $preHashAlgo),
            $hash
        );
    }
    
    /**
     * Check if password needs a rehash
     *
     * @param string $ciphertext
     * @param Key $aesKey
     * @param ?int $passwordAlgo (default: null)
     * @param array $passwordOptions (default: [])
     * @return string
     * @throws \Exception
     * @throws \InvalidArgumentException
     */
    public static function decryptAndCheckIfNeedsRehash(
        string $ciphertext,
        Key $aesKey,
        ?int $passwordAlgo = null,
        array $passwordOptions = []
    ): bool {
        $passwordAlgo = $passwordAlgo ?? static::getBestPasswordHashAlgo();
        $preHashAlgo = static::getBestPreHashAlgo($passwordAlgo);
        
        $hash = Crypto::decrypt(
            $ciphertext,
            $aesKey
        );
        
        list(
            $hash,
            $existingPreHashAlgo,
            $existingPasswordAlgo
        ) = array_values(static::getPasswordInfo($hash));
        
        if ($preHashAlgo != $existingPreHashAlgo) {
            return true;
        }
        
        return password_needs_rehash($hash, $passwordAlgo, $passwordOptions);
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
