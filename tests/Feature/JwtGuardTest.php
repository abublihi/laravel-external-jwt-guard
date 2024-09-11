<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests\Feature;

use Abublihi\LaravelExternalJwtGuard\Support\FakeTokenIssuer;
use PHPUnit\Util\Test;
use Abublihi\LaravelExternalJwtGuard\Tests\User;
use Abublihi\LaravelExternalJwtGuard\Tests\TestCase;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;

/**
 * @withMigrations
 */
class JwtGuardTest extends TestCase
{
    use DatabaseMigrations, WithLaravelMigrations, \Abublihi\LaravelExternalJwtGuard\Traits\ActingAs;

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_authenticated_user_by_jwt()
    {
        $user = User::factory()->create();

        $this->actingAsExternalJwt($user);
        
        $response = $this->getJson('current-user');

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_authenticated_admin_by_jwt()
    {
        $user = User::factory()->create();

        $this->actingAsExternalJwt($user, 'admin');
        
        $response = $this->getJson('current-admin');

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

        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->setIssuer('http://invalidissuer.com')
        );

        config([
            "externaljwtguard.authorization_servers.default.issuer" => 'http://example.com',
            'externaljwtguard.authorization_servers.default.validate_issuer' => false,
        ]);

        $response = $this->getJson('current-user');

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
        $user = User::factory()->create();

        config(['externaljwtguard.authorization_servers.default' => null]);

        $jwt = FakeTokenIssuer::user($user)->generate();

        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertUnauthorized();
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_unauthorized_with_invalid_jwt()
    {
        $user = User::factory()->create();

        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->asInvalid()
        );

        $response = $this->getJson('current-user');

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
        $user = User::factory()->makeOne();
        $user->id = 1;
        // set the create_user to false
        config(['externaljwtguard.authorization_servers.default.create_user' => false]);

        $this->actingAsExternalJwt($user);
        $response = $this->getJson('current-user');

        $response->assertStatus(401);
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_creates_and_return_authenticated_user_by_jwt()
    {
        config([
            'externaljwtguard.authorization_servers.default.create_user' => true,
        ]);

        $user = User::factory()->makeOne();
        $user->id = 1;
        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->withClaims([
                    'name' => $user->name,
                    'email' => $user->email,
                ])
        );

        $response = $this->getJson('current-user');

        $this->assertNotNull(User::where('email', $user->email)->first());
        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }
    
    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_401_when_public_key_is_not_set()
    {
        $user = User::factory()->create();

        $this->actingAsExternalJwt($user);

        config([
            'externaljwtguard.authorization_servers.default.public_key' => null,
        ]);

        $response = $this->getJson('current-user');

        $response->assertUnauthorized();
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_401_when_token_is_expired()
    {
        $user = User::factory()->create();

        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->asExpired()
        );
        
        $response = $this->getJson('current-user');

        $response->assertUnauthorized();
    }
}