<?php
/**
 * This file is a part of "cryptolabs-pk/bip32-keypair-php" package.
 * https://github.com/cryptolabs-pk/bip32-keypair-php
 *
 * Copyright (c) 2019 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/cryptolabs-pk/bip32-keypair-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace CryptoLabs\BIP32\KeyPair;

use CryptoLabs\BIP32\KeyPair;

/**
 * Class Curves
 * @package CryptoLabs\BIP32\KeyPair
 */
class Curves
{
    /** @var array */
    public const INDEX = [
        self::SECP256K1 => "Secp256k1",
        self::SECP256K1_OPENSSL => "Secp256k1_OpenSSL"
    ];

    public const SECP256K1 = 8;
    public const SECP256K1_OPENSSL = 16;

    /** @var KeyPair */
    private $keyPair;
    /** @var callable */
    private $callback;

    /**
     * Curves constructor.
     * @param KeyPair $keyPair
     * @param callable $callback
     */
    public function __construct(KeyPair $keyPair, callable $callback)
    {
        $this->keyPair = $keyPair;
        $this->callback = $callback;
    }

    /**
     * @param int $curve
     */
    private function select(int $curve): void
    {
        if (!in_array($curve, array_keys(self::INDEX))) {
            throw new \InvalidArgumentException('Cannot use an invalid ECDSA curve');
        }

        call_user_func_array($this->callback, [$curve]);
    }

    /**
     * @return void
     */
    public function secp256k1(): void
    {
        $this->select(self::SECP256K1);
    }

    /**
     * @return void
     */
    public function secp256k1_OpenSSL(): void
    {
        $this->select(self::SECP256K1_OPENSSL);
    }
}