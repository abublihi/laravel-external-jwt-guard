<?php

namespace Abublihi\LaravelExternalJwtGuard;

use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Abublihi\LaravelExternalJwtGuard\Support\JwtParser;
use Abublihi\LaravelExternalJwtGuard\Interfaces\CreateUserActionInterface;
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
        $token = $this->request->bearerToken();
        
        if (!$token) {
            throw new JwtValidationException('no bearer token is provided');
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
    public function getParsedJwt(): JwtParser
    {
        return $this->parsedJwt;
    }

    /**
     * Get the currently authenticated user.
     */
    public function user()
    {
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

        if (!$user) {
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
