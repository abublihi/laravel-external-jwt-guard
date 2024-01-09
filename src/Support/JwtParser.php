<?php

namespace Abublihi\LaravelExternalJwtGuard\Support;

use Lcobucci\JWT\JwtFacade;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint;
use Abublihi\LaravelExternalJwtGuard\Exceptions\JwtValidationException;

/**
 * This class is intended to validate and extract some information from a JWT
 */
class JwtParser
{
    private UnencryptedToken $parsedJwt;
    private bool $isJwtValid = false;

    private string $errorMessage = '';

    public function __construct(
        private string $jwt, 
        private string $publicKey,
        private string $idClaim,
        private string $rolesClaim,
        private string $algorithm = 'RS256',
        private string $issuer = '',
        private bool $validateIssuer = true
        )
    {
        if (!$this->validate()) {
            throw new JwtValidationException($this->errorMessage);
        }
    }

    private function getAlgorthemClass(): string
    {
        $algorithmClass = match ($this->algorithm) {
            // Symmetric algorithms
            'HS256' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
            'HS384' => \Lcobucci\JWT\Signer\Hmac\Sha384::class,
            'HS512' => \Lcobucci\JWT\Signer\Hmac\Sha512::class,
            'BLAKE2B' => \Lcobucci\JWT\Signer\Blake2b::class,
            // Asymmetric algorithms
            'RS256' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
            'RS384' => \Lcobucci\JWT\Signer\Rsa\Sha384::class,
            'RS512' => \Lcobucci\JWT\Signer\Rsa\Sha512::class,
            'ES256' => \Lcobucci\JWT\Signer\Ecdsa\Sha256::class,
            'ES384' => \Lcobucci\JWT\Signer\Ecdsa\Sha384::class,
            'ES512' => \Lcobucci\JWT\Signer\Ecdsa\Sha512::class,
            'EdDSA' => \Lcobucci\JWT\Signer\Eddsa::class,
            default => null,
        };

        if (!$algorithmClass) {
            throw new JwtValidationException('Unsupproted algorithm '.$this->algorithm);
        }

        return $algorithmClass;
    }

    private function validate(): bool
    {        
        $key = InMemory::plainText($this->publicKey);
        
        try {
            $token = (new JwtFacade())->parse(
                $this->jwt,
                new Constraint\SignedWith(new ($this->getAlgorthemClass()), $key),
                new Constraint\StrictValidAt(
                    new FrozenClock(now()->toDateTimeImmutable())
                )
            );
        } catch (\Exception $e) {
            $this->errorMessage = $e->getMessage();
            return false;
        }
     
        
        $this->parsedJwt = $token;
        $this->isJwtValid = true;

        return true;
    }

    public function getId(): mixed
    {
        return $this->getClaim($this->idClaim);
    } 

    public function getRoles(): mixed
    {
        return $this->getClaim($this->rolesClaim);
    }

    /**
     * @param string $name
     */
    public function getClaim(string $name): mixed
    {
        return $this->parsedJwt->claims()->get($name);
    }

    public function getIsJwtValid(): bool
    {
        return $this->isJwtValid;
    }
}