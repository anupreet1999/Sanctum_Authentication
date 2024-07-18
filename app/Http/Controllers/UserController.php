<?php

namespace App\Http\Controllers;

use App\Helpers\ApiHelper;
use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function register(RegisterRequest $request)
    {
        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);

        if ($user) {
            $success['accessToken'] = $user->createToken('Personal Access Token')->plainTextToken;
            $success['userName'] = $user->name;

            return ApiHelper::sendResponse(false, Response::HTTP_CREATED, 'Successfully created user!', $success);
        } else {
            return ApiHelper::sendResponse(false, Response::HTTP_BAD_REQUEST, 'Provide proper details');
        }
    }

    public function login(LoginRequest $request)
    {
    
        $credentials = request(['email', 'password']);
        if (!Auth::attempt($credentials)) {
            return ApiHelper::sendResponse(true, Response::HTTP_UNAUTHORIZED, 'Incorrect Login Details');
        }

        $user = Auth::user();
        $success['accessToken'] = $user->createToken('Personal Access Token')->plainTextToken;
        $success['userName'] = $user->name;
        $success['token_type'] = 'Bearer';

        return ApiHelper::sendResponse(false, Response::HTTP_OK, 'Login successful', $success);
    }

    public function getUser(Request $request)
    {
        try {
            $user = Auth::user();
    
            if (!$user) {
                return ApiHelper::sendResponse(true, Response::HTTP_UNAUTHORIZED, 'Unauthorized', [], ['message' => 'Invalid token']);
            } else {
                return ApiHelper::sendResponse(false, Response::HTTP_OK, 'User profile retrieved successfully', ['user' => $user]);

            }
    
        } catch (\Throwable $e) {
            return ApiHelper::sendResponse(true, Response::HTTP_INTERNAL_SERVER_ERROR, 'Error', [], ['message' => $e->getMessage()]);
        }
    }
}
