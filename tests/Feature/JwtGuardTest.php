<?php

namespace Abublihi\LaravelExternalJwtGuard\Tests\Feature;

use PHPUnit\Util\Test;
use Illuminate\Support\Facades\Auth;
use Orchestra\Testbench\Attributes\DefineRoute;
use Abublihi\LaravelExternalJwtGuard\Tests\User;
use Orchestra\Testbench\Attributes\WithMigration;
use Abublihi\LaravelExternalJwtGuard\JwtGuardDriver;
use Abublihi\LaravelExternalJwtGuard\Tests\TestCase;
use Abublihi\LaravelExternalJwtGuard\Support\JwtParser;
use Abublihi\LaravelExternalJwtGuard\Exceptions\CouldNotFindUserWithProvidedIdException;

#[WithMigration]
class JwtGuardTest extends TestCase
{
    #[DefineRoute('usesAuthRoutes')]
    function test_it_returns_exists_authenticated_user_by_jwt()
    {
        $user = User::factory()->create();

        $jwt = $this->issueToken(
            sub: $user->id,
            uid: $user->id,
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertSuccessful();
        $response->assertJsonPath('id', $user->id);
        $response->assertJsonPath('name', $user->name);
        $response->assertJsonPath('email', $user->email);
    }

    #[DefineRoute('usesAuthRoutes')]
    function test_it_returns_unauthorized_with_invalid_jwt()
    {
        $jwt = $this->issueToken(
            sub: 'test',
            uid: 'test',
            validToken: false
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertUnauthorized();
    }

    #[DefineRoute('usesAuthRoutes')]
    function test_it_returns_500_with_not_found_user_with_provided_id_using_jwt()
    {
        // set the create_user to false
        config(['externaljwtguard.authorization_servers.default.create_user' => false]);
        $user = User::factory()->makeOne();

        $jwt = $this->issueToken(
            sub: '1',
            uid: '1',
        );
        
        $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$jwt
            ])->getJson('current-user');

        $response->assertStatus(500);
    }

    #[DefineRoute('usesAuthRoutes')]
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
            sub: $userId,
            uid: $userId,
            customClaims: [
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

    #[DefineRoute('usesAuthRoutes')]
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
            sub: $userId,
            uid: $userId,
            customClaims: [
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

    #[DefineRoute('usesAuthRoutes')]
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
            sub: $userId,
            uid: $userId,
            customClaims: [
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
}