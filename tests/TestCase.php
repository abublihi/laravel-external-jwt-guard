<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests;

use DateTimeImmutable;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Illuminate\Contracts\Config\Repository;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Abublihi\LaravelExternalJwtGuard\Tests\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Abublihi\LaravelExternalJwtGuard\Middleware\CheckJwtRoles;
use Abublihi\LaravelExternalJwtGuard\LaravelExternalJwtGuardServiceProvider;

class TestCase extends \Orchestra\Testbench\TestCase
{
    use RefreshDatabase;

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth.providers.users.model', User::class);

        $app['config']->set('auth.guards.jwt-guard', [
            'driver' => 'external-jwt-auth',
            'provider' => 'users',
        ]);

        $app['config']->set('auth.guards.jwt-guard-admin', [
            'driver' => 'external-jwt-auth',
            'provider' => 'users',
            'auth_server_key' => 'admin',
        ]);

        $app['config']->set('externaljwtguard.authorization_servers.default', [
            'id_claim' => 'sub',
            'roles_claim' => 'roles',
            'id_attribute' => 'id',
            'create_user' => false, // it's not recommended  
            'random_password_on_creation' => false,
            'creation_claim_attribute_map' => [
                // jwt claim => database attribute
                'sub' => 'id',
                'name' => 'name', 
                'email' => 'email', 
            ],
            'issuer' => 'http://example.com',
            'validate_issuer' => true,
            'public_key' => $this->getPublicKey(), // if RSA make sure it's start with -----BEGIN PUBLIC KEY----- and ends with -----END PUBLIC KEY-----
            'signing_algorithm' => 'RS256',
            'create_user_action_class' => \Abublihi\LaravelExternalJwtGuard\Tests\CreateUserByJwtAction::class,
        ]);
        
        $app['config']->set('externaljwtguard.authorization_servers.admin', [
            'id_claim' => 'sub',
            'roles_claim' => 'roles',
            'id_attribute' => 'id',
            'create_user' => false, // it's not recommended  
            'random_password_on_creation' => false,
            'creation_claim_attribute_map' => [
                // jwt claim => database attribute
                'sub' => 'id',
                'name' => 'name', 
                'email' => 'email', 
            ],
            'issuer' => 'http://example.com',
            'validate_issuer' => true,
            'public_key' => $this->getPublicKey(), // if RSA make sure it's start with -----BEGIN PUBLIC KEY----- and ends with -----END PUBLIC KEY-----
            'signing_algorithm' => 'RS256',
            'create_user_action_class' => \Abublihi\LaravelExternalJwtGuard\Tests\CreateUserByJwtAction::class,
        ]);
        // tap($app['config'], function (Repository $config) {
            
        // });
    }

    /**
     * Define a route for current user.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    protected function usesAuthRoutes($router): void
    {
        $router->get('current-user', function(Request $request) {
            return auth()->user();
        })->middleware('auth:jwt-guard');
        
        $router->get('current-admin', function(Request $request) {
            return auth()->user();
        })->middleware('auth:jwt-guard-admin');
    }

    /**
     * Define routes for checking the CheckJwtRoles.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    protected function usesCheckJwtRolesRoutes($router): void
    {
        // check roles without auth guard
        $router->get('get-user', function(Request $request) {
            return auth()->user();
        })->middleware(CheckJwtRoles::class.':user');
        
        // check roles with web auth guard
        $router->get('get-auth-user', function(Request $request) {
            return auth()->user();
        })->middleware('auth', CheckJwtRoles::class.':user');
                
        // admin
        $router->get('get-employees', function(Request $request) {
            return auth()->user();
        })->middleware('auth:jwt-guard', CheckJwtRoles::class.':admin');

        // super-admin
        $router->get('get-admins', function(Request $request) {
            return auth()->user();
        })->middleware('auth:jwt-guard', CheckJwtRoles::class.':super-admin');
        
        // admin or manager
        $router->get('get-managers', function(Request $request) {
            return auth()->user();
        })->middleware('auth:jwt-guard', CheckJwtRoles::class.':admin|manager');
    }

    protected function getPackageProviders($app): array
    {
        return [
            LaravelExternalJwtGuardServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        // include_once __DIR__ . '/../database/migrations/create_users_table.php.stub';
        // (new \CreateUsersTable)->up();
        // perform environment setup
    }

    /**
     * @return string
     * @param array<string> $roles
     * @param string $sub
     * @param bool $validToken true
     * @param string $uid
     * @param array<int,mixed> $customClaims
     */
    protected function issueToken(
        array $roles = [],
        string $sub = '1',
        string $uid = '1',
        array $customClaims = [],
        bool $validToken = true,
        bool $expiredToken = false,
        string $issuer = 'http://example.com'): string
    {
        $signingKeyPath = $validToken? __DIR__.'/TestKeys/private.pem' : __DIR__.'/TestKeys/other_rsa256_private_key.pem';
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
        $algorithm    = new Sha256();
        $signingKey   = InMemory::file($signingKeyPath);

        $now   = new DateTimeImmutable();
        $token = $tokenBuilder
            // Configures the issuer (iss claim)
            ->issuedBy($issuer)
            // Configures the audience (aud claim)
            ->permittedFor('http://example.org')
            // Configures the subject of the token (sub claim)
            ->relatedTo($sub)
            // Configures the id (jti claim)
            ->identifiedBy('4f1g23a12aa')
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($now)
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($now->modify('-1 minute'))
            // Configures the expiration time of the token (exp claim)
            ->expiresAt($expiredToken? $now->modify('-2 minute') : $now->modify('+1 hour'))
            // Configures a new claim, called "uid"
            ->withClaim('uid', $uid)
            // add roles claim
            ->withClaim('roles', $roles)
            // Configures a new header, called "foo"
            ->withHeader('foo', 'bar');
        
        foreach ($customClaims as $claimKey => $claim) {
            $token = $token->withClaim($claimKey, $claim);
        }

        // Builds a new token
        $token = $token->getToken($algorithm, $signingKey);

        return $token->toString();
    }
   
    protected function getPublicKey()
    {
        return file_get_contents(__DIR__.'/TestKeys/public.pem');
    }

    /**
     * Resolve application core configuration implementation.
     *
     * @param  \Illuminate\Foundation\Application  $app
     *
     * @return void
     */
    protected function resolveApplicationConfiguration($app): void
    {
        parent::resolveApplicationConfiguration($app);
    }
}