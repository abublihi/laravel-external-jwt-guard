<?php

namespace Abublihi\LaravelExternalJwtGuard\Support;

use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\Authenticatable;

class CreateUserByJwt
{
    public function __construct(
        private JwtParser $parsedJwt,
        private Model $model,
        private array $authorizationServerConfig
    ) {
    }

    public function create(): Authenticatable
    {
        $creationAttributes = [];
        $creationAttributes[$this->authorizationServerConfig['id_attribute']] = $this->parsedJwt->getId();
        foreach($this->authorizationServerConfig['creation_claim_attribute_map'] as $claim => $attribute) {
            if (Str::contains($claim, '.')) {
                $explodedClaim = explode('.', $claim, 2);
                $parentClaim = @$explodedClaim[0];
                $childClaim = @$explodedClaim[1];
                $dotedClaim = Arr::dot($this->parsedJwt->getClaim($parentClaim));
                $creationAttributes[$attribute] = $dotedClaim[$childClaim];
            } else {
                $creationAttributes[$attribute] = $this->parsedJwt->getClaim($claim);
            }
        }

        if ($this->authorizationServerConfig['random_password_on_creation']) {
            $creationAttributes['password'] = Str::random(60);
        }

        // create the user in the database
        return $user = $this->model->query()->create($creationAttributes);
    }
}