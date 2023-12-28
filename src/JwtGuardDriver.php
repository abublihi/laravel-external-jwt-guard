<?php

namespace Abublihi\LaravelExternalJwtGuard;

use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

class JwtGuardDriver implements Guard
{
    use GuardHelpers;
    
    private Request $request;

    public function __construct(
        UserProvider $provider,
        Request $request
    )
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): Authenticatable|null
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $token = $this->request->bearerToken();

        if (! empty($token)) {
            $user = $this->provider->retrieveByCredentials([
                'token' => $token,
            ]);
        }

        return $this->user = $user;
    }

    /**
     * @inheritDoc
     */
    public function validate(array $credentials = [])
    {
        return $this->provider->validateCredentials([
            'token' => $this->request->bearerToken(),
        ]);
    }
}
