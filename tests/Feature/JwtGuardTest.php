<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests\Feature;

use PHPUnit\Util\Test;
use Abublihi\LaravelExternalJwtGuard\Tests\User;
use Abublihi\LaravelExternalJwtGuard\Tests\TestCase;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;
use Abublihi\LaravelExternalJwtGuard\AuthorizationServerConfig;
use Abublihi\LaravelExternalJwtGuard\Exceptions\CouldNotFindAuthorizationServerConfig;

/**
 * @withMigrations
 */
class JwtGuardTest extends TestCase
{
    use DatabaseMigrations, WithLaravelMigrations;

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_authenticated_user_by_jwt()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_authenticated_user_by_jwt_without_iss_claim_and_disabled_issuer_validation()
    {
        $user = User::factory()->create();

        // set the create_user & random_password_on_creation to true
        config([
            'externaljwtguard.authorization_servers.default.validate_issuer' => false,
        ]);

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
            [],
            true,
            'http://invalidissuer.com'
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

     /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_return_server_unauthorized_when_no_configurations_exists()
    {
        config(['externaljwtguard.authorization_servers.default' => null]);

        $jwt = $this->issueToken(
            [],
            'test',
            'test',
            [],
            false
        );

        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertUnauthorized();
        // $response->assertSeeText('Server Error');
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    // function test_it_throws_exception_when_no_configurations_exists()
    // {
    //     config(['externaljwtguard.authorization_servers.default' => null]);

    //     $this->expectException(CouldNotFindAuthorizationServerConfig::class);
    //     $this->expectExceptionMessage('could not found authorization server config with auth_server_key: default');

    //     AuthorizationServerConfig::buildFromConfigKey('default');
    // }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_unauthorized_with_invalid_jwt()
    {
        $jwt = $this->issueToken(
            [],
            'test',
            'test',
            [],
            false
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertUnauthorized();
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_unauthorized_without_jwt_header()
    {   
        $response = $this->getJson('current-user');

        $response->assertUnauthorized();
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_401_when_not_found_the_user_with_provided_id_using_jwt()
    {
        // set the create_user to false
        config(['externaljwtguard.authorization_servers.default.create_user' => false]);

        $jwt = $this->issueToken(
            [],
            '1',
            '1',
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertStatus(401);
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_creates_and_return_authenticated_user_by_jwt()
    {
        // set the create_user & random_password_on_creation to true
        config([
            'externaljwtguard.authorization_servers.default.create_user' => true,
            'externaljwtguard.authorization_servers.default.random_password_on_creation' => true,
        ]);

        $user = User::factory()->makeOne();
        $userId = 1;
        $jwt = $this->issueToken(
            [],
            $userId,
            $userId,
            [
                'name' => $user->name,
                'email' => $user->email,
            ]
        );

        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $this->assertNotNull(User::where('email', $user->email)->first());
        $response->assertSuccessful();
        $response->assertJsonPath('id', $userId);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_creates_dot_attributes_and_return_authenticated_user_by_jwt()
    {
        // set the create_user & random_password_on_creation to true
        config([
            'externaljwtguard.authorization_servers.default.create_user' => true,
            'externaljwtguard.authorization_servers.default.random_password_on_creation' => true,
            'externaljwtguard.authorization_servers.default.creation_claim_attribute_map' => [
                // jwt claim => database attribute
                'sub' => 'id',
                'employee.name' => 'name', 
                'employee.email' => 'email', 
            ],
        ]);

        $user = User::factory()->makeOne();
        $userId = 1;
        $jwt = $this->issueToken(
            [],
            $userId,
            $userId,
            [
                'employee' => [
                    'name' => $user->name,
                    'email' => $user->email,
                ],
            ]
        );

        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $this->assertNotNull(User::where('email', $user->email)->first());
        $response->assertSuccessful();
        $response->assertJsonPath('id', $userId);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_creates_second_level_dot_attributes_and_return_authenticated_user_by_jwt()
    {
        // set the create_user & random_password_on_creation to true
        config([
            'externaljwtguard.authorization_servers.default.create_user' => true,
            'externaljwtguard.authorization_servers.default.random_password_on_creation' => true,
            'externaljwtguard.authorization_servers.default.creation_claim_attribute_map' => [
                // jwt claim => database attribute
                'sub' => 'id',
                'employee.info.name' => 'name', 
                'employee.info.email' => 'email', 
            ],
        ]);

        $user = User::factory()->makeOne();
        $userId = 1;
        $jwt = $this->issueToken(
            [],
            $userId,
            $userId,
            [
                'employee' => [
                    'info' => [
                        'name' => $user->name,
                        'email' => $user->email,
                    ]
                ],
            ]
        );

        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $this->assertNotNull(User::where('email', $user->email)->first());
        $response->assertSuccessful();
        $response->assertJsonPath('id', $userId);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }
    
    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_401_when_public_key_is_not_set()
    {
        // set the create_user & random_password_on_creation to true
        config([
            'externaljwtguard.authorization_servers.default.public_key' => null,
        ]);

        $user = User::factory()->makeOne();
        $userId = 1;
        $jwt = $this->issueToken(
            [],
            $userId,
            $userId,
            [
                'employee' => [
                    'info' => [
                        'name' => $user->name,
                        'email' => $user->email,
                    ]
                ],
            ]
        );

        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        // $response->dd();
        $response->assertUnauthorized();
    }
}
