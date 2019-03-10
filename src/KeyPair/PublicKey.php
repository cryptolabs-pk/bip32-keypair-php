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

use CryptoLabs\BIP32\Exception\AddressGenerateException;
use CryptoLabs\BIP32\Exception\PublicKeyException;
use CryptoLabs\BIP32\KeyPair\PublicKey\FailSafeCurveValidate;
use CryptoLabs\BIP32\KeyPair\PublicKey\P2PKH_Address;
use CryptoLabs\BIP32\KeyPair\PublicKey\P2SH_Address;
use CryptoLabs\DataTypes\Base16;
use CryptoLabs\DataTypes\Binary;
use CryptoLabs\ECDSA\Vector;

/**
 * Class PublicKey
 * @package CryptoLabs\BIP32\KeyPair
 */
class PublicKey
{
    /** @var PrivateKey */
    private $privateKey;
    /** @var int */
    private $curve;
    /** @var \CryptoLabs\ECDSA\Vector */
    private $vector;
    /** @var Binary */
    private $publicKey;
    /** @var Binary */
    private $compressedPublicKey;

    /**
     * PublicKey constructor.
     * @param PrivateKey $keyPair
     * @throws PublicKeyException
     * @throws \CryptoLabs\ECDSA\Exception\GenerateVectorException
     * @throws \CryptoLabs\ECDSA\Exception\MathException
     */
    public function __construct(PrivateKey $keyPair)
    {
        $this->privateKey = $keyPair;
        $this->curve = $this->privateKey->curve;
        if (!$this->curve) {
            throw new PublicKeyException('Cannot generate public key; ECDSA curve is not defined');
        }

        $this->vector = Vectors::Curve($this->curve, $this->privateKey->raw());
        switch ($this->curve) {
            case Curves::SECP256K1:
            case Curves::SECP256K1_OPENSSL:
                $coords = $this->vector->coords();
                if (!$coords->x()) {
                    throw new PublicKeyException('Secp256k1 curve missing "x" point');
                } elseif (!$coords->y()) {
                    throw new PublicKeyException('Secp256k1 curve missing "y" point');
                }

                $base16x = $coords->x()->encode(false);
                $base16y = $coords->y()->encode(false);
                $bitwise = Base16::Hex2Bits($base16y);
                $sign = substr($bitwise, -1) === "0" ? "02" : "03";
                $this->publicKey = Base16::Decode($base16x . $base16y)->readOnly(true);
                $this->compressedPublicKey = Base16::Decode($sign . $base16x)->readOnly(true);
                break;
            default:
                throw new PublicKeyException(
                    sprintf('Not sure how to convert "%s" vector into public key', Curves::INDEX[$this->curve])
                );

        }
    }

    /**
     * @return Binary
     */
    public function raw(): Binary
    {
        return $this->publicKey;
    }

    /**
     * @return Binary
     * @throws PublicKeyException
     */
    public function compressed(): Binary
    {
        if (!$this->compressedPublicKey) {
            throw new PublicKeyException(
                sprintf('Could not generate a compressed public key using "%s" curve', Curves::INDEX[$this->curve])
            );
        }

        return $this->compressedPublicKey;
    }

    /**
     * @param int $prefix
     * @return P2PKH_Address
     * @throws AddressGenerateException
     */
    public function p2pkh(int $prefix): P2PKH_Address
    {
        return new P2PKH_Address($this, $prefix);
    }

    /**
     * @param int $p2pkhPrefix
     * @param int $p2shPrefix
     * @return P2SH_Address
     * @throws AddressGenerateException
     */
    public function p2sh(int $p2pkhPrefix, int $p2shPrefix): P2SH_Address
    {
        return new P2SH_Address($this->p2pkh($p2pkhPrefix), $p2shPrefix);
    }

    /**
     * @return FailSafeCurveValidate
     */
    public function failSafeCurveValidate(): FailSafeCurveValidate
    {
        return new FailSafeCurveValidate($this);
    }

    /**
     * @return int
     */
    public function curve(): int
    {
        return $this->curve;
    }

    /**
     * @return Vector
     */
    public function vector(): Vector
    {
        return $this->vector;
    }

    /**
     * @return PrivateKey
     */
    public function privateKey(): PrivateKey
    {
        return $this->privateKey;
    }
}