<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests;

use DateTimeImmutable;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Abublihi\LaravelExternalJwtGuard\Tests\User;
use Illuminate\Support\Facades\Auth;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Illuminate\Contracts\Config\Repository;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Orchestra\Testbench\Attributes\WithMigration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Abublihi\LaravelExternalJwtGuard\JwtGuardDriver;
use Abublihi\LaravelExternalJwtGuard\LaravelExternalJwtGuardServiceProvider;

#[WithMigration]
class TestCase extends \Orchestra\Testbench\TestCase
{
    use RefreshDatabase;
    
    public function setUp(): void
    {
        parent::setUp();
        // $this->afterApplicationCreated(function () {
        //     // Code after application created.
        // });

        Auth::extend('jwt-api', function ($app, string $name, array $config) { 
            return new JwtGuardDriver(Auth::createUserProvider($config['provider']), $app->make('request'));
        });
    }

       /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function defineEnvironment($app): void
    {
        tap($app['config'], function (Repository $config) {
            $config->set('auth.providers.users', [
                'driver' => 'jwt-user',
                'model' => User::class,
            ]);

            $config->set('auth.guards.jwt-guard', [
                'driver' => 'jwt-api',
                'provider' => 'users',
            ]);

            $config->set('externaljwtguard.authorization_servers.default', [
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
                'issuer' => '',
                'validate_issuer' => true,
                'public_key' => $this->getPublicKey(), // if RSA make sure it's start with -----BEGIN PUBLIC KEY----- and ends with -----END PUBLIC KEY-----
                'signing_algorithm' => 'RS256',
            ]);
        });
    }

    /**
     * Define routes setup.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    protected function usesAuthRoutes($router): void
    {
        $router->get('current-user', function(Request $request) {
            return auth()->user();
        })->middleware('auth:jwt-guard');
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
     * @param string $signingKeyPath
     * @param array<string> $roles
     */
    protected function issueToken(
        array $roles = [],
        string $sub = '1',
        string $uid = '1',
        array $customClaims = [],
        bool $validToken = true): string
    {
        $signingKeyPath = $validToken? __DIR__.'/TestKeys/private.pem' : __DIR__.'/TestKeys/other_rsa256_private_key.pem';
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
        $algorithm    = new Sha256();
        $signingKey   = InMemory::file($signingKeyPath);

        $now   = new DateTimeImmutable();
        $token = $tokenBuilder
            // Configures the issuer (iss claim)
            ->issuedBy('http://example.com')
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
            ->expiresAt($now->modify('+1 hour'))
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

        
        // $app['config']->set('auth.providers.users.model', CustomUser::class);
    }

    // #[Test]
    // #[DefineRoute('usesAuthRoutes')]
    // function test_it_returns_authenticated_user_by_jwt()
    // {
    //     $response = $this->getJson('current-user');

    //     dd($response);
    //     $response->assertSuccessful();
    // }
}