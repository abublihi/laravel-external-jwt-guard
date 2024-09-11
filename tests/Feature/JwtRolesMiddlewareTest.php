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
class JwtRolesMiddlewareTest extends TestCase
{
    use DatabaseMigrations, WithLaravelMigrations, \Abublihi\LaravelExternalJwtGuard\Traits\ActingAs;

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_is_not_authorized_when_user_is_not_authenticated()
    {
        $response = $this->getJson('get-user');

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

        $this->actingAsExternalJwt($user);
        
        $response = $this->getJson('get-employees');

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

        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->withClaims([
                    'roles' => ['admin']
                ])
        );
        $response = $this->getJson('get-employees');
        
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
        
        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->withClaims([
                    'roles' => ['super-admin', 'other', 'roles']
                ])
        );

        $response = $this->getJson('get-admins');
        
        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_not_allowed_while_having_other_roles()
    {
        $user = User::factory()->create();

        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->withClaims([
                    'roles' => ['notadmin']
                ])
        );
        
        $response = $this->getJson('get-managers'); // should have either admin or manager

        $response->assertForbidden();
        $response->assertSee('User does not have the right roles.');
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_allowed_when_haveing_right_roles()
    {
        $user = User::factory()->create();

        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->withClaims([
                    'roles' => ['admin']
                ])
        );
        
        $response = $this->getJson('get-managers'); // admin|manager

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);


        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->withClaims([
                    'roles' => ['manager']
                ])
        );
        
        $response = $this->getJson('get-managers'); // admin|manager

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);

        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->withClaims([
                    'roles' => ['manager', 'admin']
                ])
        );

        $response = $this->getJson('get-managers'); // admin|manager

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    /**
     * @test
     * @define-route usesCheckJwtRolesRoutes
     */
    function test_user_allowed_when_having_multiple_jwt_roles()
    {
        $user = User::factory()->create();

        $this->actingAsExternalJwt(
            FakeTokenIssuer::user($user)
                ->withClaims([
                    'roles' => ['other-role', 'manager', 'user'],
                ])
        );

        
        $response = $this->getJson('get-managers'); // admin|manager

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }
}