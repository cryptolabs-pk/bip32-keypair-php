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

namespace CryptoLabs\BIP32;

use CryptoLabs\BIP32\KeyPair\Curves;
use CryptoLabs\BIP32\KeyPair\PublicKey;
use CryptoLabs\DataTypes\Binary;

/**
 * Class KeyPair
 * @package CryptoLabs\BIP32
 */
class KeyPair
{
    /** @var null|KeyPair */
    private $parent;
    /** @var Binary */
    private $privateKey;
    /** @var null|int */
    private $curve;
    /** @var null|PublicKey */
    private $publicKey;

    /**
     * KeyPair constructor.
     * @param Binary $privateKey
     * @param KeyPair|null $parent
     */
    public function __construct(Binary $privateKey, ?KeyPair $parent = null)
    {
        $this->parent = $parent;
        $this->privateKey = $privateKey;
        $this->privateKey->readOnly(true); // Set buffer to read-only state
    }

    /**
     * @param string $prop
     * @param $value
     * @return KeyPair
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
     * @return Curves
     */
    public function curves(): Curves
    {
        return new Curves($this, function (int $curve) {
            $this->set("curve", $curve);
        });
    }

    /**
     * @return int|null
     */
    public function getEllipticCurve(): ?int
    {
        if ($this->curve) {
            return $this->curve;
        }

        if ($this->parent) {
            return $this->parent->getEllipticCurve();
        }

        return null;
    }

    /**
     * @return Binary
     */
    public function privateKey(): Binary
    {
        return $this->privateKey;
    }

    /**
     * @return PublicKey
     * @throws Exception\KeyPairException
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