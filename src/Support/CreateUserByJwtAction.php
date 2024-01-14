<?php

namespace Abublihi\LaravelExternalJwtGuard\Support;

use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Abublihi\LaravelExternalJwtGuard\AuthorizationServerConfig;
use Abublihi\LaravelExternalJwtGuard\Interfaces\CreateUserActionInterface;
use Abublihi\LaravelExternalJwtGuard\Exceptions\CouldNotCreateUserException;

class CreateUserByJwtAction implements CreateUserActionInterface
{
    /**
     * @throws CouldNotCreateUserException
     */
    public function create(
        UserProvider $userProvider,
        JwtParser $parsedJwt, 
        AuthorizationServerConfig $authorizationServerConfig): Authenticatable
    {
        // NOTE: the only provider supports creating the user is Eloquent 
        if (!$userProvider instanceof EloquentUserProvider){ 
            throw new CouldNotCreateUserException("User Provider is not supported only Eloquent User provider is supported.");
        }

        $userModelClass = $userProvider->getModel();
        /**
         * @var \Illuminate\Database\Eloquent\Model
         */
        $userModel = new $userModelClass;


        $creationAttributes = [];
        $creationAttributes[$authorizationServerConfig->idAttribute] = $parsedJwt->getId();
        foreach($authorizationServerConfig->creationClaimAttributeMap as $claim => $attribute) {
            if (Str::contains($claim, '.')) {
                $explodedClaim = explode('.', $claim, 2);
                $parentClaim = @$explodedClaim[0];
                $childClaim = @$explodedClaim[1];
                $dotedClaim = Arr::dot($parsedJwt->getClaim($parentClaim));
                $creationAttributes[$attribute] = $dotedClaim[$childClaim];
            } else {
                $creationAttributes[$attribute] = $parsedJwt->getClaim($claim);
            }
        }

        if ($authorizationServerConfig->randomPasswordOnCreation) {
            $creationAttributes['password'] = Str::random(60);
        }

        // create the user in the database
        try {
            $user = $userModel->query()->create($creationAttributes);
        } catch (\Exception $e) {
            throw new CouldNotCreateUserException($e->getMessage());
        }

        return $user;
    }
}