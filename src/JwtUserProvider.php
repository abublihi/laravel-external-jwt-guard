<?php

declare(strict_types=1);

namespace Abublihi\LaravelExternalJwtGuard;

use Abublihi\LaravelExternalJwtGuard\Support\CreateUserByJwt;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Abublihi\LaravelExternalJwtGuard\Support\JwtParser;
use Abublihi\LaravelExternalJwtGuard\Exceptions\JwtValidationException;
use Abublihi\LaravelExternalJwtGuard\Exceptions\CouldNotFindUserWithProvidedIdException;

class JwtUserProvider implements UserProvider
{
    /**
     * Model class should implement \Illuminate\Database\Eloquent\Model
     *
     * @var Model
     */
    private Model $model;

    private Request $request;
    
    private string $authorizationServerKey;

    private array|null $authorizationServerConfig;
    
    private JwtParser $parsedJwt;
    /**
     * Initializes the Jwt user provider
     *
     * @param string $model
     * @param Request $request
     */
    public function __construct(string $model, Request $request, string $authorizationServerKey = 'default')
    {
        $modelClass = '\\'.ltrim($model, '\\');
        $this->model = new $modelClass;
        $this->request = $request;
        $this->authorizationServerKey = $authorizationServerKey;
        $this->authorizationServerConfig = config("externaljwtguard.authorization_servers.$this->authorizationServerKey");
    }

    private function parseJwt(string|null $token): JwtParser
    {
        return new JwtParser(
            jwt: $token,
            publicKey: $this->authorizationServerConfig['public_key'],
            idClaim: $this->authorizationServerConfig['id_claim'],
            rolesClaim: $this->authorizationServerConfig['roles_claim'],
            algorithm: $this->authorizationServerConfig['signing_algorithm'],
            issuer: $this->authorizationServerConfig['issuer'],
            validateIssuer: $this->authorizationServerConfig['validate_issuer'],
        );
    }

    public function retrieveById($identifier)
    {
        return null;
    }

    public function retrieveByToken($identifier, $token)
    {
        return null;
    }

    public function updateRememberToken(Authenticatable $user, $token): void
    {}
    
    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials['token'])) {
            return null;
        }

        try {
            $parsedJwt = $this->parseJwt($credentials['token']);
        } catch (JwtValidationException $e) {
            return null;
        }

        $user = $this->model
            ->query()
            ->where($this->authorizationServerConfig['id_attribute'], $parsedJwt->getId())
            ->first();

        if (! $user && $this->authorizationServerConfig['create_user']) {
            $user = (new CreateUserByJwt($parsedJwt, $this->model, $this->authorizationServerConfig))->create();
        }

        if (! $user) {
            throw new CouldNotFindUserWithProvidedIdException("id_attribute: {$this->authorizationServerConfig['id_attribute']}, auth server id: {$parsedJwt->getId()}");
        }

        return $user;
    }

    public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        if (empty($credentials['token'])) {
            return false;
        }

        try {
            $parsedJwt = $this->parseJwt($credentials['token']);
        } catch (JwtValidationException $e) {
            return false;
        }
        

        return $parsedJwt->getIsJwtValid();
    }
}