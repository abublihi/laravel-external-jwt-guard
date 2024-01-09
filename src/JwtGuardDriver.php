<?php

namespace Abublihi\LaravelExternalJwtGuard;

use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Abublihi\LaravelExternalJwtGuard\Support\JwtParser;
use Abublihi\LaravelExternalJwtGuard\Support\CreateUserByJwtAction;
use Abublihi\LaravelExternalJwtGuard\Exceptions\CouldNotFindUserWithProvidedIdException;

class JwtGuardDriver implements Guard
{
    use GuardHelpers;
    
    private Request $request;
    private AuthorizationServerConfig $authorizationServerConfig;
    private JwtParser $parsedJwt;

    public function __construct(
        UserProvider $provider,
        Request $request,
        string $authorizationServerKey = 'default'
    ) {
        $this->provider = $provider;
        $this->request = $request;
        $this->authorizationServerConfig = AuthorizationServerConfig::buildFromConfigKey($authorizationServerKey);

        $this->parsedJwt = $this->parseJwt();
    }

    private function parseJwt(): JwtParser
    {
        return new JwtParser(
            jwt: $this->request->bearerToken(),
            publicKey: $this->authorizationServerConfig->publicKey,
            idClaim: $this->authorizationServerConfig->idClaim,
            rolesClaim: $this->authorizationServerConfig->roleClaim,
            algorithm: $this->authorizationServerConfig->signingAlgorithm,
            issuer: $this->authorizationServerConfig->issuer,
            validateIssuer: $this->authorizationServerConfig->validateIssuer,
        );
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): Authenticatable|null
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = $this->provider->retrieveByCredentials(
            [
                $this->authorizationServerConfig->idAttribute => $this->parsedJwt->getId(),
            ]
        );

        if (! $user  
            && $this->authorizationServerConfig->createUser  
            // && $this->provider instanceof EloquentUserProvider // NOTE: the only provider supports creating the user is Eloquent 
        ) {
            $user = (new $this->authorizationServerConfig->createUserActionClass)->create(
                $this->provider,
                $this->parsedJwt,
                $this->authorizationServerConfig
            );
        }

        if (! $user) {
            throw new CouldNotFindUserWithProvidedIdException("id_attribute: {$this->authorizationServerConfig->idAttribute}, auth server id: {$this->parsedJwt->getId()}");
        }

        return $this->user = $user;
    }

    /**
     * @inheritDoc
     */
    public function validate(array $credentials = [])
    {
        return $this->parsedJwt->getIsJwtValid();
    }
}
