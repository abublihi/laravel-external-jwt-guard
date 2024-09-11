<?php

namespace Abublihi\LaravelExternalJwtGuard;

class AuthorizationServerConfig
{
    public string $publicKey;
    public string $idClaim;
    public string|null $roleClaim;
    public string $idAttribute;
    public string $signingAlgorithm;
    public bool $validateIssuer;
    public string $issuer;
    public bool $createUser;
    public string|null $createUserActionClass;
    
    /** 
     * @param array $creationClaimAttributeMap
     */
    public function __construct(
        string $publicKey,
        string $idClaim,
        string|null $roleClaim,
        string $idAttribute,
        string $signingAlgorithm,
        bool $validateIssuer,
        string $issuer,
        bool $createUser,
        string|null $createUserActionClass,
    )
    {
        $this->publicKey = $publicKey;
        $this->idClaim = $idClaim;
        $this->roleClaim = $roleClaim;
        $this->idAttribute = $idAttribute;
        $this->signingAlgorithm = $signingAlgorithm;
        $this->validateIssuer = $validateIssuer;
        $this->issuer = $issuer;
        $this->createUser = $createUser;
        $this->createUserActionClass = $createUserActionClass;
    }
    
    /**
     * @return self
     */
    public static function buildFromConfigKey(string $authorizationServerKey): self|null
    {
        $authServerConfig = config("externaljwtguard.authorization_servers.$authorizationServerKey");
        // loading config from config file
        if (is_null($authServerConfig)) {
            return null;
        }

        return new self(
            $authServerConfig['public_key'] ?? '',
            $authServerConfig['id_claim'],
            $authServerConfig['roles_claim'] ?? null,
            $authServerConfig['id_attribute'],
            $authServerConfig['signing_algorithm'] ?? 'RS256',
            $authServerConfig['validate_issuer'] ?? true,
            $authServerConfig['issuer'] ?? '',
            $authServerConfig['create_user'] ?? false,
            $authServerConfig['create_user_action_class'] ?? null
        );
    }
}