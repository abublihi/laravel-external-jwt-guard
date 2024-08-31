<?php

namespace Abublihi\LaravelExternalJwtGuard\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use OpenSSLAsymmetricKey;
class ActingAs
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
    )
    {
        $this->user = $user;

        $this->privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);
        
        $this->fakePrivateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);

        $this->publicKey = openssl_pkey_get_details($this->privateKey)['key'];
    }

    public static function user(Authenticatable $user)
    {
        return new self($user);
    }

    public function withClaims(array $claims)
    {
        $this->claims = $claims;

        return $this;
    }

    public function asInvalid()
    {
        $this->valid = false;

        return $this;
    }
    
    public function asExpired()
    {
        $this->expired = false;

        return $this;
    }

    

}