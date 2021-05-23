
# Armor - SSH Keys Extension

An extension for the [Armor package](https://github.com/apexpl/armor/) that provides functionality for management of public SSH keys.

## Installation

Install via Composer with:

> `composer require apex/armor-sshkeys`


## Key Manager

One library is included, the `Apex\Armor\SshKeys\KeyManager` class that contains the following methods:

* array generate(string $uuid, ?string $password = null, bool $save_privkey = false) - Generates a new 4096 bit RSA key, and encodes it to public SSH key.  Returns array with two elements, "pubkey" and "privkey".
* void import(string $uuid, string $public_key)
* array getPublic(string $uuid) - Returns array of all public SSH keys assigned to uuid.
* ?string getPrivate(string $uuid, string $password) = Should be avoided, as you shouldn't be storing private keys.
* bool delete(string $uuid, string $public_key)
* int deleteUuid(string $uuid) - Returns number of keys deleted


## Basic Usage

~~~php
use Apex\Armor\Armor;
use Apex\Armor\SshKeys\KeyManager;

// Init Armor
$armor = new Armor();
$manager = new KeyManager($armor);

// Generate
$res = $manager->generate('u:511');
echo "Pvi Key: $res[privkey]\n";
echo "Pub Key: $res[pubkey]\n";
~~~

## Support

If you have any questions, issues or feedback, please feel free to drop a note on the <a href="https://reddit.com/r/apexpl/">ApexPl Reddit sub</a> for a prompt and helpful response.


## Follow Apex

Loads of good things coming in the near future including new quality open source packages, more advanced articles / tutorials that go over down to earth useful topics, et al.  Stay informed by joining the <a href="https://apexpl.io/">mailing list</a> on our web site, or follow along on Twitter at <a href="https://twitter.com/mdizak1">@mdizak1</a>.



