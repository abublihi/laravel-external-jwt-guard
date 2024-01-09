<?php

namespace Abublihi\LaravelExternalJwtGuard\Interfaces;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Abublihi\LaravelExternalJwtGuard\Support\JwtParser;
use Abublihi\LaravelExternalJwtGuard\AuthorizationServerConfig;
use Abublihi\LaravelExternalJwtGuard\Exceptions\CouldNotCreateUserException;

interface CreateUserActionInterface
{
    /**
     * @throws CouldNotCreateUserException
     */
    public function create(
        UserProvider $userProvider,
        JwtParser $parsedJwt, 
        AuthorizationServerConfig $authorizationServerConfig): Authenticatable;
}