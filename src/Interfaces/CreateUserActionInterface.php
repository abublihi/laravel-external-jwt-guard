<?php

namespace Abublihi\LaravelExternalJwtGuard\Interfaces;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Abublihi\LaravelExternalJwtGuard\Support\JwtParser;
use Abublihi\LaravelExternalJwtGuard\AuthorizationServerConfig;

interface CreateUserActionInterface
{
    public function create(
        UserProvider $userProvider,
        JwtParser $parsedJwt, 
        AuthorizationServerConfig $authorizationServerConfig): Authenticatable|null;
}