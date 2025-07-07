This Package dose not provide much, it's simplly a driver for authentication for laravel, so it's better to have your own code without installing the pacakge.

Here I will guide you throw a basic instruction to add it to your project without the need to install the package.

---

## 1. Install lcobucci/jwt

If you haven’t already, install `lcobucci/jwt` package:

```bash
composer require lcobucci/jwt
```

---

## 2. Create the JWT parser

Create a service or a support class to parse JWTs & the execption below

```php name=app/Services/JwtParser.php
<?php

namespace App\Support;

use Illuminate\Support\Arr;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint;
use App\Exceptions\JwtValidationException;

/**
 * This class is intended to validate and extract some information from a JWT
 */
class JwtParser
{
    private UnencryptedToken $parsedJwt;
    private bool $isJwtValid = false;

    private string $algorithmClass = \Lcobucci\JWT\Signer\Rsa\Sha256::class;
    private string $errorMessage = '';
    private array $claims;
    private string $jwt;
    private string $publicKey;
    private string $idClaim;
    private string|null $rolesClaim;
    private string $issuer = '';
    private bool $validateIssuer = true;
    
    public function __construct(
        string $jwt,
        string $idClaim,
        string $publicKey,
        string|null $rolesClaim,
        string $issuer = '',
        bool $validateIssuer = true
        )
    {
        $this->jwt = $jwt;
        $this->publicKey = $publicKey;
        $this->idClaim = $idClaim;
        $this->rolesClaim = $rolesClaim;
        $this->issuer = $issuer;
        $this->validateIssuer = $validateIssuer;
        
        if (!$this->validate()) {
            throw new JwtValidationException($this->errorMessage);
        }

        $this->claims = Arr::dot($this->parsedJwt->claims()->all()); // not required
    }

    private function validate(): bool
    {       
        try {
            $key = InMemory::plainText($this->publicKey);
        } catch (\Exception $e) {
            $this->errorMessage = $e->getMessage();
            return false;
        }
            
        try {
            $token = (new JwtFacade())->parse(
                $this->jwt,
                new Constraint\SignedWith(new $this->algorithmClass, $key),
                new Constraint\StrictValidAt(
                    new FrozenClock(now()->toDateTimeImmutable())
                )
            );
        } catch (\Exception $e) {
            $this->errorMessage = $e->getMessage();
            return false;
        }
        
        $this->parsedJwt = $token;

        if ($this->validateIssuer) {
            $iss = $this->getClaim('iss');
            if (empty($iss)) {
                $this->errorMessage = 'iss claim not found in the JWT, could not validate issuer, you should disable validating the issuer';
                return false;
            }

            if ($iss != $this->issuer) {
                $this->errorMessage = "Issuer is not valid token issued by: $iss, and it should be issued by {$this->issuer}";
                return false;
            }
        }

        $this->isJwtValid = true;

        return true;
    }

    public function getId()
    {
        return $this->claims[$this->idClaim] ?? null;
    }

    public function getRoles()
    {
        return $this->rolesClaim ? $this->getClaim($this->rolesClaim) : null;
    }

    /**
     * @param string $name
     */
    public function getClaim(string $name)
    {
        return $this->parsedJwt->claims()->get($name);
    }

    public function getIsJwtValid(): bool
    {
        return $this->isJwtValid;
    }
}
```

```php name=app/Exceptions/JwtValidationException.php
<?php

namespace App\Exceptions;

use Illuminate\Auth\AuthenticationException;

class JwtValidationException extends AuthenticationException
{
    // 
}
```


## 3. Create the Custom Guard

Create a guard class that uses lcobucci/jwt to validate the JWT.

```php name=app/Auth/Guards/ExternalJwtGuard.php
<?php

namespace App\Auth\Guards;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
ues App\Services\JwtParser;

class JwtGuardDriver implements Guard
{
    use GuardHelpers;

    private JwtParser|null $parsedJwt;

    public function __construct(
        UserProvider $provider,
    ) {
        $this->provider = $provider;

        $this->parseJwt();
    }

    private function parseJwt(): JwtParser|null
    {
        $token = request()->bearerToken();
        
        if (!$token) {
            return $this->parsedJwt = null;
        }

        // you should validate the configurations 
        return $this->parsedJwt = new JwtParser(
            $token,
            config('external_jwt_auth.id_claim'),
            config('external_jwt_auth.public_key'),
            config('external_jwt_auth.role_claim'),
            config('external_jwt_auth.public_key'),
            config('external_jwt_auth.issuer'),
            config('external_jwt_auth.validate_issuer'),
        );
    }

    /**
     * Get's the parsed jwt
     * 
     * @return JwtParser 
     */
    public function getParsedJwt(): JwtParser|null
    {
        return $this->parsedJwt ?? $this->parseJwt();
    }

    /**
     * Get the currently authenticated user.
     */
    public function user()
    {
        $this->getParsedJwt();

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
        return $this->getParsedJwt()?->getIsJwtValid() ?? false;
    }
}
```

---

## 4. Register the Guard

In your AuthServiceProvider:

```php name=app/Providers/AuthServiceProvider.php
use Illuminate\Support\Facades\Auth;
use App\Auth\Guards\ExternalJwtGuard;

public function boot()
{
    $this->registerPolicies();

    Auth::extend('external-jwt', function ($app, string $name, array $config) { 
        return new ExternalJwtGuard(Auth::createUserProvider($config['provider']));
    });
}
```

---

## 5. Configure the Guard

In `config/auth.php`:

```php name=config/auth.php
'guards' => [
    // ...
    'external-jwt' => [
        'driver' => 'external-jwt',
        'provider' => 'users',
    ],
],
```

---

## 6. Use the Guard in Routes

```php name=routes/api.php
Route::middleware('auth:external-jwt')->get('/user', function (Request $request) {
    return $request->user();
});
```

## Notes
- Adjust your siging algorthem based on your SSO configuration by changing the value of the attribute $algorithmClass in JwtParser class.
- Adjust how you retrieve the user from the JWT payload according to your JWT claims' structure.
- You can add more validation constraints as needed (issuer, audience, etc.).
