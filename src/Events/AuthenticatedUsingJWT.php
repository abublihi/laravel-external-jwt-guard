<?php

namespace Abublihi\LaravelExternalJwtGuard\Events;

use \Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Foundation\Events\Dispatchable;

class AuthenticatedUsingJWT
{
    use Dispatchable, SerializesModels;

    public Authenticatable $user;

    public function __construct(Authenticatable $user)
    {
        $this->user = $user;
    }
}