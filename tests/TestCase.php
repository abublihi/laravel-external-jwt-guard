<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests;

use Illuminate\Http\Request;
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
            'signing_algorithm' => 'RS256',
            'create_user_action_class' => \Abublihi\LaravelExternalJwtGuard\Tests\CreateUserByJwtAction::class,
        ]);
        
        $app['config']->set('externaljwtguard.authorization_servers.admin', [
            'id_claim' => 'sub',
            'id_attribute' => 'id',
        ]);
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