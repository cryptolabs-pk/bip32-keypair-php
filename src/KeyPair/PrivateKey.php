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

/**
 * Class PrivateKey
 * @package CryptoLabs\BIP32
 * @property-read null|int $curve
 */
class PrivateKey
{
    /** @var Binary */
    protected $privateKey;
    /** @var null|int */
    protected $curve;
    /** @var null|PublicKey */
    protected $publicKey;

    /**
     * PrivateKey constructor.
     * @param Binary $entropy
     */
    public function __construct(Binary $entropy)
    {
        $this->privateKey = $entropy;
        $this->privateKey->readOnly(true); // Set buffer to read-only state
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [sprintf('%d-bit Private Key', $this->privateKey->length()->bits())];
    }

    /**
     * @param string $prop
     * @param $value
     * @return PrivateKey
     */
    public function set(string $prop, $value): self
    {
        if ($prop === "curve") {
            if (!is_int($value) || !in_array($value, array_keys(Curves::INDEX))) {
                throw new \InvalidArgumentException('Cannot use an invalid ECDSA curve');
            }

            $this->$prop = $value;
            return $this;
        }

        throw new \DomainException('Cannot set value of inaccessible property');
    }

    /**
     * @param string $prop
     * @return int|null
     */
    public function __get(string $prop)
    {
        switch ($prop) {
            case "curve":
                return $this->curve;
        }

        throw new \DomainException('Cannot get value of inaccessible property');
    }

    /**
     * @return Curves
     */
    public function curves(): Curves
    {
        return new Curves(function (int $curve) {
            $this->set("curve", $curve);
        });
    }

    /**
     * @return Binary
     */
    public function raw(): Binary
    {
        return $this->privateKey;
    }

    /**
     * @return PublicKey
     * @throws \CryptoLabs\BIP32\Exception\PublicKeyException
     * @throws \CryptoLabs\ECDSA\Exception\GenerateVectorException
     * @throws \CryptoLabs\ECDSA\Exception\MathException
     */
    public function publicKey(): PublicKey
    {
        if (!$this->publicKey) {
            $this->publicKey = new PublicKey($this);
        }

        return $this->publicKey;
    }
}