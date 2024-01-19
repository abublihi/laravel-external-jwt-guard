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

    private string $jwt;
    private string $publicKey;
    private string $idClaim;
    private string $rolesClaim;
    private string $algorithm = 'RS256';
    private string $issuer = '';
    private bool $validateIssuer = true;
    
    public function __construct(
        string $jwt, 
        string $idClaim,
        string $publicKey,
        string $rolesClaim,
        string $algorithm = 'RS256',
        string $issuer = '',
        bool $validateIssuer = true
        )
    {
        $this->jwt = $jwt;
        $this->publicKey = $publicKey;
        $this->idClaim = $idClaim;
        $this->rolesClaim = $rolesClaim;
        $this->algorithm = $algorithm;
        $this->issuer = $issuer;
        $this->validateIssuer = $validateIssuer;

        if (!$this->validate()) {
            throw new JwtValidationException($this->errorMessage);
        }
    }

    private function getAlgorithmClass(): string
    {
        $algorithmClass = null;
        switch ($this->algorithm) {
            // Symmetric algorithms
            case 'HS256': 
                $algorithmClass = \Lcobucci\JWT\Signer\Hmac\Sha256::class;
                break;
            case 'HS384': 
                $algorithmClass = \Lcobucci\JWT\Signer\Hmac\Sha384::class;
                break;
            case 'HS512': 
                $algorithmClass = \Lcobucci\JWT\Signer\Hmac\Sha512::class;
                break;
            case 'BLAKE2B': 
                $algorithmClass = \Lcobucci\JWT\Signer\Blake2b::class;
                break;
            // Asymmetric algorithms
            case 'RS256': 
                $algorithmClass = \Lcobucci\JWT\Signer\Rsa\Sha256::class;
                break;
            case 'RS384': 
                $algorithmClass = \Lcobucci\JWT\Signer\Rsa\Sha384::class;
                break;
            case 'RS512': 
                $algorithmClass = \Lcobucci\JWT\Signer\Rsa\Sha512::class;
                break;
            case 'ES256': 
                $algorithmClass = \Lcobucci\JWT\Signer\Ecdsa\Sha256::class;
                break;
            case 'ES384': 
                $algorithmClass = \Lcobucci\JWT\Signer\Ecdsa\Sha384::class;
                break;
            case 'ES512': 
                $algorithmClass = \Lcobucci\JWT\Signer\Ecdsa\Sha512::class;
                break;
            case 'EdDSA': 
                $algorithmClass = \Lcobucci\JWT\Signer\Eddsa::class;
                break;
        }

        if (!$algorithmClass) {
            throw new JwtValidationException('Unsupproted algorithm '.$this->algorithm);
        }

        return $algorithmClass;
    }

    private function validate(): bool
    {        
        $key = InMemory::plainText($this->publicKey);
        $className = $this->getAlgorithmClass();
    
        try {
            $token = (new JwtFacade())->parse(
                $this->jwt,
                new Constraint\SignedWith(new $className, $key),
                new Constraint\StrictValidAt(
                    new FrozenClock(now()->toDateTimeImmutable())
                )
            );
        } catch (\Exception $e) {
            $this->errorMessage = $e->getMessage();
            return false;
        }
        
        $this->parsedJwt = $token;

        if ($this->validateIssuer) {
            $iss = $this->getClaim('iss');
            if (empty($iss)) {
                $this->errorMessage = 'iss claim not found in the JWT, could not validate issuer, you should disable validating the issuer';
                return false;
            }

            if ($iss != $this->issuer) {
                $this->errorMessage = "Issuer is not valid token issued by: $iss, and it should be issued by {$this->issuer}";
                return false;
            }
        }

        $this->isJwtValid = true;

        return true;
    }

    public function getId()
    {
        return $this->getClaim($this->idClaim);
    } 

    public function getRoles()
    {
        return $this->getClaim($this->rolesClaim);
    }

    /**
     * @param string $name
     */
    public function getClaim(string $name)
    {
        return $this->parsedJwt->claims()->get($name);
    }

    public function getIsJwtValid(): bool
    {
        return $this->isJwtValid;
    }
}