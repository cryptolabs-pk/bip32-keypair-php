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

namespace BIP32;

use CryptoLabs\BIP32\KeyPair\PrivateKey;
use CryptoLabs\DataTypes\Base16;

/**
 * Class BIP32
 * @package BIP32
 */
class BIP32
{
    /**
     * @param Base16 $entropy
     * @return PrivateKey
     */
    public static function PrivateKey(Base16 $entropy): PrivateKey
    {
        return new PrivateKey($entropy);
    }

    /**
     * @param string $hexits
     * @return PrivateKey
     */
    public static function PrivateKeyFromHexits(string $hexits): PrivateKey
    {
        return self::PrivateKey(new Base16($hexits));
    }
}