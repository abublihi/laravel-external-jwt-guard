<?php

namespace Abublihi\LaravelExternalJwtGuard;

use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Abublihi\LaravelExternalJwtGuard\Support\JwtParser;
use Abublihi\LaravelExternalJwtGuard\Interfaces\CreateUserActionInterface;
use Abublihi\LaravelExternalJwtGuard\Exceptions\JwtValidationException;
use Abublihi\LaravelExternalJwtGuard\Exceptions\CouldNotFindUserWithProvidedIdException;

class JwtGuardDriver implements Guard
{
    use GuardHelpers;

    private AuthorizationServerConfig|null $authorizationServerConfig;
    private JwtParser|null $parsedJwt;

    public function __construct(
        UserProvider $provider,
        string $authorizationServerKey = 'default'
    ) {
        $this->provider = $provider;
        $this->authorizationServerConfig = AuthorizationServerConfig::buildFromConfigKey($authorizationServerKey);

        $this->parsedJwt = $this->parseJwt();
    }

    private function parseJwt(): JwtParser|null
    {
        $token = request()->bearerToken();
        
        if (!$token || !$this->authorizationServerConfig) {
            return null;
        }

        return new JwtParser(
            $token,
            $this->authorizationServerConfig->idClaim,
            $this->authorizationServerConfig->publicKey,
            $this->authorizationServerConfig->roleClaim,
            $this->authorizationServerConfig->signingAlgorithm,
            $this->authorizationServerConfig->issuer,
            $this->authorizationServerConfig->validateIssuer,
        );
    }

    /**
     * Get's the parsed jwt
     * 
     * @return JwtParser 
     */
    public function getParsedJwt(): JwtParser|null
    {
        return $this->parsedJwt;
    }

    /**
     * Get the currently authenticated user.
     */
    public function user()
    {
        $this->parsedJwt = $this->parsedJwt ?? $this->parseJwt();

        if (!$this->authorizationServerConfig || !$this->parsedJwt) {
            return $this->user;
        }

        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (!is_null($this->user)) {
            return $this->user;
        }

        $user = $this->provider->retrieveByCredentials(
            [
                $this->authorizationServerConfig->idAttribute => $this->parsedJwt->getId(),
            ]
        );

        if (
            !$user
            && $this->authorizationServerConfig->createUser
        ) {
            /**
             * @var CreateUserActionInterface
             */
            $actionObject = new $this->authorizationServerConfig->createUserActionClass;
            $user = $actionObject->create(
                $this->provider,
                $this->parsedJwt,
                $this->authorizationServerConfig
            );
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
