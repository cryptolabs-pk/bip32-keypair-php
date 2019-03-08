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

use CryptoLabs\BIP32\Exception\KeyPairException;
use CryptoLabs\BIP32\KeyPair;
use CryptoLabs\DataTypes\Base16;
use CryptoLabs\DataTypes\Binary;
use CryptoLabs\ECDSA\Vector;

/**
 * Class PublicKey
 * @package CryptoLabs\BIP32\KeyPair
 */
class PublicKey
{
    /** @var KeyPair */
    private $keyPair;
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
     * @param KeyPair $keyPair
     * @throws KeyPairException
     * @throws \CryptoLabs\ECDSA\Exception\GenerateVectorException
     * @throws \CryptoLabs\ECDSA\Exception\MathException
     */
    public function __construct(KeyPair $keyPair)
    {
        $this->keyPair = $keyPair;
        $this->curve = $this->keyPair->getEllipticCurve();
        if (!$this->curve) {
            throw new KeyPairException('Cannot generate public key; ECDSA curve is not defined');
        }

        $this->vector = Vectors::Curve($this->curve, $this->keyPair->privateKey());
        switch ($this->curve) {
            case Curves::SECP256K1:
            case Curves::SECP256K1_OPENSSL:
                $coords = $this->vector->coords();
                if (!$coords->x()) {
                    throw new KeyPairException('Secp256k1 curve missing "x" point');
                } elseif (!$coords->y()) {
                    throw new KeyPairException('Secp256k1 curve missing "y" point');
                }

                $base16x = $coords->x()->encode(false);
                $base16y = $coords->y()->encode(false);
                $bitwise = Base16::Hex2Bits($base16y);
                $sign = substr($bitwise, -1) === "0" ? "02" : "03";
                $this->publicKey = Base16::Decode($base16x . $base16y);
                $this->compressedPublicKey = Base16::Decode($sign . $base16x);
                break;
            default:
                throw new KeyPairException(
                    sprintf('Not sure how to convert "%s" vector into public key', Curves::INDEX[$this->curve])
                );

        }
    }

    /**
     * @return Binary
     */
    public function original(): Binary
    {
        return $this->publicKey;
    }

    /**
     * @return Binary
     * @throws KeyPairException
     */
    public function compressed(): Binary
    {
        if (!$this->compressedPublicKey) {
            throw new KeyPairException(
                sprintf('Could not generate a compressed public key using "%s" curve', Curves::INDEX[$this->curve])
            );
        }

        return $this->compressedPublicKey;
    }

    /**
     * @return FailSafeValidate
     */
    public function failSafeValidate(): FailSafeValidate
    {
        return new FailSafeValidate($this);
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
     * @return KeyPair
     */
    public function keyPair(): KeyPair
    {
        return $this->keyPair;
    }
}