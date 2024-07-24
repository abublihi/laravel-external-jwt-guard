<?php

namespace Abublihi\LaravelExternalJwtGuard;

use Abublihi\LaravelExternalJwtGuard\Exceptions\CouldNotFindAuthorizationServerConfig;

class AuthorizationServerConfig
{
    public string $publicKey;
    public string $idClaim;
    public string $roleClaim;
    public string $idAttribute;
    public string $signingAlgorithm;
    public bool $validateIssuer;
    public string $issuer;
    public bool $createUser;
    public string $createUserActionClass;
    /**
     * @var array
     */
    public array $creationClaimAttributeMap;
    public bool $randomPasswordOnCreation;

    /** 
     * @param array $creationClaimAttributeMap
     * @throws CouldNotFindAuthorizationServerConfig
     */
    public function __construct(
        string $publicKey,
        string $idClaim,
        string $roleClaim,
        string $idAttribute,
        string $signingAlgorithm,
        bool $validateIssuer,
        string $issuer,
        bool $createUser,
        string $createUserActionClass,
        array $creationClaimAttributeMap,
        bool $randomPasswordOnCreation
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
        $this->creationClaimAttributeMap = $creationClaimAttributeMap;
        $this->randomPasswordOnCreation = $randomPasswordOnCreation;
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
            // throw new CouldNotFindAuthorizationServerConfig('could not found authorization server config with auth_server_key: '.$authorizationServerKey);
        }

        return new self(
            $authServerConfig['public_key'] ?? '',
            $authServerConfig['id_claim'],
            $authServerConfig['roles_claim'],
            $authServerConfig['id_attribute'],
            $authServerConfig['signing_algorithm'] ?? 'RS256',
            $authServerConfig['validate_issuer'] ?? true,
            $authServerConfig['issuer'] ?? '',
            $authServerConfig['create_user'] ?? false,
            $authServerConfig['create_user_action_class'],
            $authServerConfig['creation_claim_attribute_map'],
            $authServerConfig['random_password_on_creation'],
        );
    }
}