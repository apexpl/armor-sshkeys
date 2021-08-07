<?php
declare(strict_types = 1);

namespace Apex\Armor\SshKeys;

use OpenSSLAsymmetricKey;

/**
 * Private to public ssh
 */
class PrivateToSshPublic
{

    /**
     * RSA to SSH pub key
     */
    public static function get(OpenSSLAsymmetricKey $privkey):string
    {

        $keyInfo = openssl_pkey_get_details($privkey);
        $buffer = pack("N", 7) . "ssh-rsa" .
            self::sshEncodeBuffer($keyInfo['rsa']['e']) . 
            self::sshEncodeBuffer($keyInfo['rsa']['n']);

        // Return
        return "ssh-rsa " . base64_encode($buffer);
    }

    /**
     * Encode SSH buffer
     */
    public static function sshEncodeBuffer($buffer) 
    {
        $len = strlen($buffer);
        if (ord($buffer[0]) & 0x80) {
            $len++;
            $buffer = "\x00" . $buffer;
        }
        return pack("Na*", $len, $buffer);
    }

}

