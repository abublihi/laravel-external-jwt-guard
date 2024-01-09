<?php

return [
    'authorization_servers' => [
        'default' => [
            /*
             |--------------------------------------------------------------------------
             | Identification settings:
             |--------------------------------------------------------------------------
             */
            
            'id_claim' => env('JWT_GUARD_ID_CLAIM', 'sub'),
            'roles_claim' => env('JWT_GUARD_ROLES_CLAIM', 'roles'),
            
            /**
             * This will be used to match the id_claim with the id in the corresponding model
             * 
             * Example: 
             * if you have configured a guard with the following 
             * 
               'guards' => [
                    'api' => [
                        'driver' => 'external-jwt-auth', // our driver
                        'provider' => 'users',
                    ],
                ]
             * 
             * Then the package will look into your provider with the id attribute and the claim `where('id_attribute', '=', 'id_claim')`
             */
            'id_attribute' => env('JWT_GUARD_ID_ATTRIBUTE', 'id'),

            /*
             |--------------------------------------------------------------------------
             | Creation setting:
             |--------------------------------------------------------------------------
             */

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
                'sub' => 'id',
                'name' => 'name', 
            ],

            /*
             |--------------------------------------------------------------------------
             | Validation settings:
             |--------------------------------------------------------------------------
             */

            'issuer' => '',
            'validate_issuer' => true,
            'public_key' => env('JWT_GUARD_AUTH_SERVER_PUBLIC_KEY'), // if RSA make sure it's start with -----BEGIN PUBLIC KEY----- and ends with -----END PUBLIC KEY-----
            'signing_algorithm' => env('JWT_GUARD_AUTH_SIGN_ALG', 'RS256'),
        ],
        // you could add as many as you want of the authorization servers by duplicating the configurations above ^^
        // 'other' => [ 'id_claim' => '' ..... ]
    ],
];