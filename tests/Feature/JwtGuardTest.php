<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests\Feature;

use Abublihi\LaravelExternalJwtGuard\Events\AuthenticatedUsingJWT;
use PHPUnit\Util\Test;
use Illuminate\Support\Facades\Event;
use Abublihi\LaravelExternalJwtGuard\Tests\User;
use Abublihi\LaravelExternalJwtGuard\Tests\TestCase;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;

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
    function test_it_returns_authenticated_admin_by_jwt()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-admin');

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_event__authenticated_using_jwt_is_dispatched()
    {
        Event::fake();

        $user = User::factory()->create();

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        Event::assertDispatched(AuthenticatedUsingJWT::class, function(AuthenticatedUsingJWT $event) use ($user) {
            return $event->user->id == $user->id;
        });

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

        config([
            'externaljwtguard.authorization_servers.default.validate_issuer' => false,
        ]);

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
            [],
            true,
            false,
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
        config([
            'externaljwtguard.authorization_servers.default.create_user' => true,
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
    function test_it_returns_401_when_public_key_is_not_set()
    {
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

        $response->assertUnauthorized();
    }

    /**
     * @test
     * @define-route usesAuthRoutes
     */
    function test_it_returns_401_when_token_is_expired()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
            [],
            true,
            true
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertUnauthorized();
    }
}
