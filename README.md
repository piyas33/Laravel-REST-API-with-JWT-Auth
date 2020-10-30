# Laravel-REST-API-with-JWT-Auth
Laravel REST API with JWT(JSON Web Token) Authentication.

## Install JWT
```
composer require tymon/jwt-auth
```
N.B. : If face any probem(Laravel 5.8) to install JWT token - 
```
"require": {
        ...
        "tymon/jwt-auth": "dev-developer"
    },
```
than ' coposer update '

## Add service provider ( Laravel 5.4 or below )(config/app.php) 
```
'providers' => [

    ...

    Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
]

```
### Publish the Package config
```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```
N.B. : You should now have a config/jwt.php file that allows you to configure the basics of this package.

### Generate secret key
```
php artisan jwt:secret
```
### In Environment (.env) file
```
JWT_SECRET=v0fSb74o11TPfNgObVqNGDnXBwmydN232wIWZPP5xqzqVi7IyPQnSY7SsvR3Ez1fSjh
```
### User.php
```
<?php

namespace App;

use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    // Rest omitted for brevity

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}

```
### Configure Auth guard
##### config/auth.php
```
'defaults' => [
    'guard' => 'api',   //web to api
    'passwords' => 'users',
],

...

'guards' => [
    'api' => [
        'driver' => 'jwt',  //token to jwt(web.php for token and api.php for jwt)
        'provider' => 'users',
    ],
],
```

### Add some basic authentication routes

```
Route::group([

    'prefix' => 'auth'

], function () {

    Route::post('register', 'ApiController@login');
    Route::post('login', 'ApiController@login');
    Route::post('logout', 'ApiController@logout');
    
    Route::post('user_list', 'ApiController@getAllUser');

});
```

### Create the ApiController

```
php artisan make:controller ApiController
```

### Now open this ApiController and paste this below code

app/Http/Controllers/ApiController.php
```
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;

class AuthController extends Controller
{
    public $loginAfterSignUp = true;
        
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    public function register(RegisterAuthRequest $request)
    {
        $data = [
            'name' => $request->name,
            'email' => $request->name,
            'password' => $request->name
        ];
        
        User::create($data);
 
        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }
 
        return response()->json([
            'success' => true,
            'data' => $data
        ], Response::HTTP_OK);
    }
    
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ])
    }
        
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    public function getAllUser()
    {
        return response()->json(auth()->user());
    }
}
```

