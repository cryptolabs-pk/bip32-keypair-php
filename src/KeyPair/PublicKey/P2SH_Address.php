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

namespace CryptoLabs\BIP32\KeyPair\PublicKey;

use CryptoLabs\Base58\Base58Check;
use CryptoLabs\Base58\Result\Base58Encoded;
use CryptoLabs\BIP32\Exception\AddressGenerateException;
use CryptoLabs\DataTypes\Base16;
use CryptoLabs\DataTypes\Binary;

/**
 * Class P2SH_Address
 * @package CryptoLabs\BIP32\KeyPair\PublicKey
 */
class P2SH_Address
{
    /** @var P2PKH_Address */
    private $p2pkh_Address;
    /** @var int */
    private $prefix;
    /** @var Base58Check */
    private $base58check;
    /** @var Binary */
    private $hash160;

    /**
     * P2SH_Address constructor.
     * @param P2PKH_Address $p2pkh_Address
     * @param int $prefix
     * @throws AddressGenerateException
     */
    public function __construct(P2PKH_Address $p2pkh_Address, int $prefix)
    {
        $this->p2pkh_Address = $p2pkh_Address;
        $this->usePrefix($prefix);
        $this->base58check = new Base58Check();
    }

    /**
     * @param int $prefix
     * @return P2SH_Address
     * @throws AddressGenerateException
     */
    public function usePrefix(int $prefix): self
    {
        if ($prefix < 0) {
            throw new AddressGenerateException('P2SH prefix must be a positive integer');
        }

        $this->prefix = $prefix;
        return $this;
    }

    /**
     * @return int
     */
    public function prefix(): int
    {
        return $this->prefix;
    }

    /**
     * @return Binary
     * @throws \CryptoLabs\BIP32\Exception\PublicKeyException
     */
    public function hash160(): Binary
    {
        if (!$this->hash160) {
            $p2pkhPrefixHex = dechex($this->p2pkh_Address->prefix());
            if (strlen($p2pkhPrefixHex) % 2 !== 0) {
                $p2pkhPrefixHex = "0" . $p2pkhPrefixHex;
            }

            $hash160_raw = $p2pkhPrefixHex . "14" . $this->p2pkh_Address->hash160()->get()->base16(false);
            $hash160 = new Base16($hash160_raw);
            $hash160->hash()->sha256()
                ->hash()->ripeMd160();

            $this->hash160 = $hash160;
            $this->hash160->readOnly(true);
        }

        return $this->hash160;
    }

    /**
     * @return Base58Encoded
     * @throws \CryptoLabs\BIP32\Exception\PublicKeyException
     */
    public function address(): Base58Encoded
    {
        $prefixHexits = dechex($this->prefix);
        if (strlen($prefixHexits) % 2 !== 0) {
            $prefixHexits = "0" . $prefixHexits;
        }

        return $this->base58check->encode($prefixHexits . $this->hash160()->get()->base16(false));
    }
}