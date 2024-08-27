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
        if ($this->app->runningInConsole()) {
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
        Auth::extend('external-jwt-auth', function ($app, string $name, array $config) { 
            return new JwtGuardDriver(Auth::createUserProvider($config['provider']), @$config['auth_server_key']?: 'default');
        });
        
        // Automatically apply the package configuration
        // $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'externaljwtguard');
    }
}
