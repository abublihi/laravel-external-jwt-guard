<?php

namespace Abublihi\LaravelExternalJwtGuard;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Foundation\Application;
use Abublihi\LaravelExternalJwtGuard\JwtUserProvider;

class LaravelExternalJwtGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     */
    public function boot()
    {
        Auth::provider('jwt-user', function (Application $app, array $config) { 
            return new JwtUserProvider($config['model'], $app['request'], @$config['auth_server']?: 'default');
        });
        
        if (function_exists('config_path')) { // function not available and 'publish' not relevant in Lumen
            $this->publishes([
                __DIR__.'/../config/config.php' => config_path('externaljwtguard.php'),
            ], 'config');
        }
    }

    /**
     * Register the application services.
     */
    public function register()
    {
        // Automatically apply the package configuration
        // $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'externaljwtguard');
    }
}
