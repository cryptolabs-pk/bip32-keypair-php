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

use CryptoLabs\DataTypes\Binary;
use CryptoLabs\ECDSA\ECDSA;
use CryptoLabs\ECDSA\Vector;

/**
 * Class Vectors
 * @package CryptoLabs\BIP32\KeyPair
 */
class Vectors
{
    /**
     * @param int $curve
     * @param Binary $privateKey
     * @return Vector
     * @throws \CryptoLabs\ECDSA\Exception\GenerateVectorException
     * @throws \CryptoLabs\ECDSA\Exception\MathException
     */
    public static function Curve(int $curve, Binary $privateKey): Vector
    {
        switch ($curve) {
            case Curves::SECP256K1:
                return ECDSA::Secp256k1()->vectorFromPrivateKey($privateKey);
            case Curves::SECP256K1_OPENSSL:
                return ECDSA::Secp256k1_OpenSSL()->vectorFromPrivateKey($privateKey);
            default:
                throw new \InvalidArgumentException('Invalid ECDSA curve');
        }
    }
}