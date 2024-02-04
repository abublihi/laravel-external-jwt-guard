# Laravel External JWT Guard

[![Latest Version on Packagist](https://img.shields.io/packagist/v/abublihi/laravel-external-jwt-guard.svg?style=flat-square)](https://packagist.org/packages/abublihi/laravel-external-jwt-guard)
[![Total Downloads](https://img.shields.io/packagist/dt/abublihi/laravel-external-jwt-guard.svg?style=flat-square)](https://packagist.org/packages/abublihi/laravel-external-jwt-guard)
![GitHub Actions](https://github.com/abublihi/laravel-external-jwt-guard/actions/workflows/main.yml/badge.svg)

This package provides a simple custom authentication guard for Laravel using an external JWT provided by an OAuth server or Any type of SSO that uses a JWT. Below a figure describe the flow.

![](https://github.com/abublihi/laravel-external-jwt-guard/assets/10172039/20ca24cf-7684-4fc6-a9ce-515823a5a7da)

## Installation

You can install the package via composer:

```bash
composer require abublihi/laravel-external-jwt-guard
```

publish the configuration file `externaljwtguard.php`

```bash
php artisan vendor:publish --provider="Abublihi\LaravelExternalJwtGuard\LaravelExternalJwtGuardServiceProvider" --tag config
```
## Usage

The package is very simple but also powerful when it comes to customization, After installation and publishing of the configurations you should first configure your `default` authorization server,

> NOTE: The package allow you to add multiple authorization servers but for mostly use cases you only need one authorization server. 

### Configure your Authorization server

please head to configuration file `config/externaljwtguard.php`, the configurations is separated in three main Sections: 

- Identification settings 
- Creation setting (optional)
- Validation settings

#### Identification settings

First will go over the configuration of `Identification settings`, as the name denotes, the `Identification settings` is the configurations that allows the package to identify the user by using the JWT claims.

> NOTE: please make sure these are configured well.


| Name | Description | Required? |
| ----------- | ----------- | ----------- |
| id_claim | the claim provided in The JWT by your SSO that identifies the user, for example UUID or Email it should be Unique | Yes |
| roles_claim | the claim where your SSO put the Roles of the user | No |
| id_attribute | the attribute in your system of the package can match by the id_claim | Yes |

> NOTE: id_attribute is in your system, the package use it to identify the authenticated user for example if you have configured the guard to a provider that is configured to a User model the package will look for the id_attribute and match it with the id_claim from the JWT

```php
'id_claim' => env('JWT_GUARD_ID_CLAIM', 'sub'),
'roles_claim' => env('JWT_GUARD_ROLES_CLAIM', 'roles'), // not yet used
'id_attribute' => env('JWT_GUARD_ID_ATTRIBUTE', 'id'), // in your database (e.g. users table)
```

#### Creation setting (optional)

The creation setting is used to configure how will create a user if not exists in the system, you can disable this feature and we encourage disabling it. 

| Name | Description | Required? |
| ----------- | ----------- | ----------- |
| create_user | boolean (to disable or enable the creation of the user if not exists) | No |
| create_user_action_class | An action class for creation of a user (default: \Abublihi\LaravelExternalJwtGuard\Support\CreateUserByJwtAction::class) | No, yes if create_user=true |
| random_password_on_creation | boolean (to randomly set a password attribute as a random value while creation of a user) | No |
| creation_claim_attribute_map | array of mapping the claim (from jwt) to the attribute (your model) | No,yes if create_user=true |

> NOTE: You can use your own action to create the user but you should implement the interface `Abublihi\LaravelExternalJwtGuard\Interfaces\CreateUserActionInterface`

```php
'create_user' =>  env('JWT_GUARD_CREATE_USER', false),
// you can define your own action by implementing the interface Abublihi\LaravelExternalJwtGuard\Interfaces\CreateUserActionInterface
'create_user_action_class' => \Abublihi\LaravelExternalJwtGuard\Support\CreateUserByJwtAction::class,
// create random password for the newly created user if password attribute exists on the database table, 
// and you set the create_user to true you should also set this to true
'random_password_on_creation' => env('JWT_GUARD_CREATE_USER', false),
// this will set the user data for creation from the jwt claims
'creation_claim_attribute_map' => [
    // jwt_claim => database_attribute
    // 'employee.email' => 'email' // you can look for a claim using dot(.) this will get employee claim and then look for the email in employee claim
    // 'sub' => 'id',
    // 'name' => 'name', 
],
```

#### Validation settings

| Name | Description | Required? |
| ----------- | ----------- | ----------- |
| issuer | the issuer of the JWT | No, yes if validate_issuer=true |
| validate_issuer | boolean (validate the issuer or not) | No |
| public_key | the public key of your authorization server | Yes |
| signing_algorithm | the signing algorithm of your authorization server | Yes |

```php
'issuer' => 'https://example.com',
'validate_issuer' => true,
'public_key' => env('JWT_GUARD_AUTH_SERVER_PUBLIC_KEY'), // if RSA, make sure it's start with -----BEGIN PUBLIC KEY----- and ends with -----END PUBLIC KEY-----
'signing_algorithm' => env('JWT_GUARD_AUTH_SIGN_ALG', 'RS256'),
```

### Guard Configuration 

After we have configured our Authorization server next we have to configure the our guard in `config/auth.php`

in the Guards you can add/modify the guards where you want to use JWT as authentication guard by setting the driver to `external-jwt-auth` .

```php
'guards' => [
    .
    .
    'api-jwt' => [
        'driver' => 'external-jwt-auth', // <-- here you have to set the drive to `external-jwt-auth`
        'provider' => 'users',
    ],
    .
    .
],
```

### Test your configuration

Add a route in for example `routes/api.php`

```php
Route::middleware('auth:api-jwt')->group(function() {
    Route::get('user', function(){
        return request()->user(); // <-- will return the user which is configured
    });
});
```

## JWT role middleware

The package also comes with a role middleware that checks the roles of the JWT (User), you should configure it right first by using the config file `roles_claim` to the right roles claim which should be an **array** of roles. to use the middleware you have two options: 

1. define an **alias** in `app/Http/Kernel.php` 
2. use it directly without an alias

### Defining the middleware Alias in the kernel 

Go to `app/Http/Kernel.php` and add the following line

> NOTE: The name of the alias could be any thing

```php
protected $middlewareAliases = [
    // ...
    'jwt-role' => \Abublihi\LaravelExternalJwtGuard\Middleware\CheckJwtRoles::class
];
```

Using the middleware in the routes

```php
Route::group(['middleware' => ['auth:api-jwt' 'jwt-role:manager']], function () {
    // this will allow any jwt with the role `manager`
});
```

You can specify multiple roles with a | (pipe) character, which is treated as OR

```php
Route::group(['middleware' => ['auth:api-jwt' 'jwt-role:manager|super-admin']], function () {
    // this will allow any jwt with the role `manager` or `super-admin`
});
```

### Using the Middleware directly without defining it on the kernel


```php
use Abublihi\LaravelExternalJwtGuard\Middleware\CheckJwtRoles;

Route::group(['middleware' => ['auth:api-jwt' CheckJwtRoles::class.':manager']], function () {
    // this will allow any jwt with the role `manager`
});
```


Example JWT with roles claim

```json
{
  "iss": "http://example.com",
  "aud": "http://example.org",
  "sub": "2",
  "jti": "4f1g23a12aa",
  "iat": 1707071173.863238,
  "nbf": 1707071113.863238,
  "exp": 1707074773.863238,
  "uid": "2",
  "roles": [
    "manager",
    "super-admin"
  ]
}
```


### Testing

```bash
composer test
```

### Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

### Security

If you discover any security related issues, please email abublihi@gmail.com instead of using the issue tracker.

## Credits

-   [Abublihi](https://github.com/abublihi)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
