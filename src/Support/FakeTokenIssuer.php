<?php

namespace Abublihi\LaravelExternalJwtGuard\Support;

use DateTimeImmutable;
use OpenSSLAsymmetricKey;
use Illuminate\Support\Str;
use Lcobucci\JWT\Token\Builder;
use Illuminate\Support\Facades\Log;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Illuminate\Contracts\Auth\Authenticatable;

class FakeTokenIssuer
{
    public Authenticatable $user;
    public string $authorizationServer = 'default';
    public bool $valid = true;
    public bool $expired = false;
    public array $claims = [];
    public bool $validateIssuer = true;
    public string $issuer = 'http://example.com';
    private OpenSSLAsymmetricKey|false $privateKey;
    private OpenSSLAsymmetricKey|false $fakePrivateKey;
    private string $publicKey;

    public function __construct(
        Authenticatable $user,
        string $authorizationServer = 'default',
    )
    {
        Log::warning('Generating a fake token: This should only be on the testing environment see: Abublihi\LaravelExternalJwtGuard\Support\ActingAs');

        $this->authorizationServer = $authorizationServer;
        $this->user = $user;

        $this->privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);
        
        $this->fakePrivateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);

        $this->publicKey = openssl_pkey_get_details($this->privateKey)['key'];
    }

    public static function user(Authenticatable $user): self
    {
        return new self($user);
    }

    public function withClaims(array $claims): self
    {
        $this->claims = $claims;

        return $this;
    }

    public function asInvalid(): self
    {
        $this->valid = false;

        return $this;
    }
    
    public function asExpired(): self
    {
        $this->expired = false;

        return $this;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function generate(): string
    {
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
        $algorithm = new Sha256();
        $privateKey = null;        
        openssl_pkey_export($this->valid? $this->privateKey : $this->fakePrivateKey, $privateKey);
        $signingKey = InMemory::plainText($privateKey);

        $now   = new DateTimeImmutable();
        $token = $tokenBuilder
            ->issuedBy($this->issuer)
            // Configures the subject of the token (sub claim)
            ->relatedTo($this->user->getAuthIdentifier())
            // Configures the id (jti claim)
            ->identifiedBy(Str::random())
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($now)
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($now->modify('-1 minute'))
            // Configures the expiration time of the token (exp claim)
            ->expiresAt($this->expired? $now->modify('-10 minute') : $now->modify('+1 hour'));
        
        foreach ($this->claims as $claimKey => $claim) {
            $token = $token->withClaim($claimKey, $claim);
        }

        // Builds a new token
        $token = $token->getToken($algorithm, $signingKey);

        return $token->toString();
    }
}