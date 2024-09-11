<?php

namespace Abublihi\LaravelExternalJwtGuard\Traits;

use Abublihi\LaravelExternalJwtGuard\Support\FakeTokenIssuer;
use Illuminate\Contracts\Auth\Authenticatable;

trait ActingAs
{
    public function setExternalJwtConfig(FakeTokenIssuer $token, string $authorizationServer = 'default')
    {
        config([
            "externaljwtguard.authorization_servers.$authorizationServer.id_claim" => 'sub',
            "externaljwtguard.authorization_servers.$authorizationServer.issuer" => $token->issuer,
            "externaljwtguard.authorization_servers.$authorizationServer.validate_issuer" => $token->validateIssuer,
            "externaljwtguard.authorization_servers.$authorizationServer.public_key" => $token->getPublicKey(),
            "externaljwtguard.authorization_servers.$authorizationServer.signing_algorithm" =>  "RS256",
        ]);
    }

    public function actingAsExternalJwt(FakeTokenIssuer|Authenticatable $tokenOrUser, $authorizationServer = 'default')
    {
        if ($tokenOrUser instanceof Authenticatable) {
            $tokenOrUser = FakeTokenIssuer::user($tokenOrUser);
        }

        $this->setExternalJwtConfig($tokenOrUser, $authorizationServer);
        $this->withHeader('Authorization', 'Bearer '.$tokenOrUser->generate());
    }
}