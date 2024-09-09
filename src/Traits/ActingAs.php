<?php

namespace Abublihi\LaravelExternalJwtGuard\Traits;

use Abublihi\LaravelExternalJwtGuard\Support\FakeTokenIssuer;

trait ActingAs
{
    public function setExternalJwtConfig(FakeTokenIssuer $token)
    {
        config([
            "externaljwtguard.authorization_servers.$token->authorizationServer.id_claim" => 'sub',
            "externaljwtguard.authorization_servers.$token->authorizationServer.issuer" => $token->issuer,
            "externaljwtguard.authorization_servers.$token->authorizationServer.validate_issuer" => $token->validateIssuer,
            "externaljwtguard.authorization_servers.$token->authorizationServer.public_key" => $token->getPublicKey(),
            "externaljwtguard.authorization_servers.$token->authorizationServer.signing_algorithm" =>  "RS256",
        ]);
    }

    public function actingAsExternalJwt(FakeTokenIssuer $token)
    {
        $this->setExternalJwtConfig($token);
        $this->withHeader('Authorization', 'Bearer '.$token->generate());
    }
}