<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests\Feature;

use PHPUnit\Util\Test;
use Abublihi\LaravelExternalJwtGuard\Tests\User;
use Abublihi\LaravelExternalJwtGuard\Tests\TestCase;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;

/**
 * @withMigrations
 */
class JwtRolesMiddlewareTest extends TestCase
{
    use DatabaseMigrations, WithLaravelMigrations;

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_is_not_authorized_when_user_is_not_authenticated()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$jwt
        ])->getJson('get-user');

        $response->assertUnauthorized();
        $response->assertSee('User is not authorized.');
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_throws_exception_when_auth_configuration_is_set_to_different_driver()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
        );
               
        $response = $this->actingAs($user)->getJson('get-auth-user');
        $response->assertStatus(500);
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_forbidden_when_dose_not_have_required_roles()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            [],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$jwt
        ])->getJson('get-employees');

        $response->assertForbidden();
        $response->assertSee('User does not have the right roles.');
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_allowed_when_have_required_role()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            ['admin'],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$jwt
        ])->getJson('get-employees');
        
        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_allowed_when_have_multiple_roles_with_required_role()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            ['super-admin', 'other', 'roles'],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$jwt
        ])->getJson('get-admins');
        
        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_not_allowed_when_using_role_or_directive()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            ['notadmin'],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$jwt
        ])->getJson('get-managers'); // admin|manager

        $response->assertForbidden();
        $response->assertSee('User does not have the right roles.');
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_allowed_when_using_role_or_directive()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            ['admin'],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$jwt
        ])->getJson('get-managers'); // admin|manager

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_allowed_when_using_role_or_directive_with_multiple_jwt_roles()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            ['other-role', 'manager', 'user'],
            $user->id,
            $user->id,
        );
        
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$jwt
        ])->getJson('get-managers'); // admin|manager

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }
}