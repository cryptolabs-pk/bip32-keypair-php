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

use CryptoLabs\BIP32\Exception\FailSafeValidateException;
use CryptoLabs\BIP32\KeyPair\Curves;
use CryptoLabs\BIP32\KeyPair\PublicKey;
use CryptoLabs\BIP32\KeyPair\Vectors;

/**
 * Class FailSafeCurveValidate
 * @package CryptoLabs\BIP32\KeyPair\PublicKey
 */
class FailSafeCurveValidate extends Curves
{
    /**
     * FailSafeValidate constructor.
     * @param PublicKey $publicKey
     */
    public function __construct(PublicKey $publicKey)
    {
        parent::__construct(function (int $curve) use ($publicKey) {
            if ($publicKey->curve() === $curve) {
                throw new FailSafeValidateException('Fail-safe ECDSA curve cannot be same as primary one');
            }

            $failSafeVector = Vectors::Curve($curve, $publicKey->privateKey()->raw());
            switch ($curve) {
                case Curves::SECP256K1:
                case Curves::SECP256K1_OPENSSL:
                    $matchX = $publicKey->vector()->coords()->x()->equals($failSafeVector->coords()->x());
                    $matchY = $publicKey->vector()->coords()->y()->equals($failSafeVector->coords()->y());
                    if (!$matchX || !$matchY) {
                        throw new FailSafeValidateException('Fail-safe vector does NOT match');
                    }

                    return;
            }

            throw new FailSafeValidateException(
                sprintf(
                    'Cannot fail-safe validate ECDSA curve "%s" with "%s"',
                    Curves::INDEX[$publicKey->curve()],
                    Curves::INDEX[$curve]
                )
            );
        });
    }
}