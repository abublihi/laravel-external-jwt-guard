<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests;

use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Abublihi\LaravelExternalJwtGuard\Support\JwtParser;
use Abublihi\LaravelExternalJwtGuard\AuthorizationServerConfig;
use Abublihi\LaravelExternalJwtGuard\Interfaces\CreateUserActionInterface;

class CreateUserByJwtAction implements CreateUserActionInterface
{
    public function create(
        UserProvider $userProvider,
        JwtParser $parsedJwt, 
        AuthorizationServerConfig $authorizationServerConfig): Authenticatable|null
    {
        $userModelClass = $userProvider->getModel();
        /**
         * @var \Illuminate\Database\Eloquent\Model
         */
        $userModel = new $userModelClass;


        // create the user in the database
        try {
            $user = $userModel->query()->create([
                'id' => $parsedJwt->getId(),
                'name' => $parsedJwt->getClaim('name'),
                'email' => $parsedJwt->getClaim('email'),
                'password' => Str::random(60)
            ]);
        } catch (\Exception $e) {
            return null;
        }

        return $user;
    }
}