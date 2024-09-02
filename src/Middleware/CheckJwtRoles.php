<?php

namespace Abublihi\LaravelExternalJwtGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Abublihi\LaravelExternalJwtGuard\JwtGuardDriver;
use Abublihi\LaravelExternalJwtGuard\Exceptions\InvaildGuardException;

class CheckJwtRoles
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     * @throws InvaildGuardException
     */
    public function handle(Request $request, Closure $next, string $requiredRoles = null): Response
    {
        if (!auth()->check()) {
            abort(401, 'User is not authorized.');
        }

        if (!Auth::guard() instanceof JwtGuardDriver) {
            throw new InvaildGuardException('CheckJwtRoles should only used with JwtGuardDriver (external-jwt-auth), currently used: '.get_class(auth()->guard()));
        }

        /**
         * @var JwtGuardDriver $auth
         */
        $auth = auth();
        $jwtRoles = $auth->getParsedJwt()->getRoles();

        if ($requiredRoles && empty($jwtRoles)) {
            abort(403, __('User does not have the right roles.'));
        }

        $requiredRoles = explode('|', $requiredRoles);

        foreach ($requiredRoles as $role) {
            if (in_array($role, $jwtRoles)) {
                return $next($request);
            }
        }

        abort(403, __('User does not have the right roles.'));
    }
}
