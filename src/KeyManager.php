<?php
declare(strict_types = 1);

namespace Apex\Armor\SshKeys;

use Apex\Armor\Armor;
use Apex\Armor\SshKeys\PrivateToPublicSsh;
use Apex\Container\Di;
use Apex\Db\Interfaces\DbInterface;
use Apex\Armor\Exceptions\{ArmorDuplicateKeyException, ArmorInvalidKeyPasswordException, ArmorUuidNotExistsException};


/**
 * RSA key management
 */
class KeyManager
{

    /**
     * Constructor
     */
    public function __construct(
        private Armor $armor
    ) { 
        $this->db = Di::get(DbInterface::class);
    }

    /**
     * Generate key-pair
     */
    public function generate(string $uuid, ?string $password = null, bool $save_privkey = false):array
    {

        // Set config args
        $config = array(
            "digest_alg" => "sha512",
            "private_key_bits" => 4096,
            "private_key_type" => OPENSSL_KEYTYPE_RSA 
        );
        $res = openssl_pkey_new($config);

        // Export key-pair
        openssl_pkey_export($res, $privkey, $password);
        $pubkey = $this->privateToSshPublic($res);

        // Encrypt private key
        if ($save_privkey === true) { 
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
            $enc_privkey = openssl_encrypt($privkey, 'aes-256-cbc', hash('sha256', $password), 0, $iv);
            $iv = base64_encode($iv);
        } else {
            list($enc_privkey, $iv) = ['', ''];
        }

        // Add to database
        $this->db->insert('armor_keys', [
            'uuid' => $uuid, 
            'algo' => 'ssh', 
            'iv' => $iv, 
            'public_key' => $pubkey, 
            'private_key' => $enc_privkey]
        );

        // Return
        return [
            'privkey' => $privkey, 
            'pubkey' => $pubkey
        ];
    }

    /**
     * RSA to SSH pub key
     */
    public function privateToSshPublic($privkey)
    {
        return PrivateToPublicSsh::get($privkey);
    }

    /**
     * Import public key
     */
    public function import(string $uuid, string $public_key):void
    {

            // Add to db
        $this->db->insert('armor_keys', [
            'uuid' => $uuid, 
            'algo' => 'ssh', 
            'public_key' => $public_key
        ]);

    }

    /**
     * Get public keys
     */
    public function getPublic(string $uuid):array
    {
        $keys = $this->db->getColumn("SELECT public_key FROM armor_keys WHERE uuid = %s AND algo = 'ssh'", $uuid);
        return $keys;
    }

    /**
     * Get private key
     */
    public function getPrivate(string $uuid, string $password, bool $is_ascii = true):string
    {

        // Check database
        if (!$row = $this->db->getRow("SELECT * FROM armor_keys WHERE uuid = %s AND algo = 'ssh'", $uuid)) { 
            return null;
        }

        // Hash password, if needed
        if ($is_ascii === true) { 
            $password = hash('sha256', $password);
        }

        // Decrypt private key
        if (!$privkey = openssl_decrypt($row['private_key'], 'aes-256-cbc', $password, 0, base64_decode($row['iv']))) { 
            throw new ArmorInvalidKeyPasswordException("Unable to retrive private RSA key for uuid '$uuid' as the password provided is incorrect.");
        }

        // Return
        return $privkey;
    }

    /**
     * Delete key
     */
    public function delete(string $uuid, string $public_key):bool
    {
        $stmt = $this->db->query("DELETE FROM armor_keys WHERE uuid = %s AND algo = 'ssh' AND public_key = %s", $uuid, $public_key);
        return $this->db->numRows($stmt) > 0 ? true : false;
    }

    /**
     * Delete uuid
     */
    public function deleteUuid(string $uuid):int
    {
        $stmt = $this->db->query("DELETE FROM armor_keys WHERE uuid = %s AND algo = 'ssh'", $uuid);
        return $this->db->numRows($stmt);
    }

}


