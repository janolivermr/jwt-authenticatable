<?php

declare(strict_types=1);

namespace Janolivermr\JwtAuthenticatable;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use InvalidArgumentException;
use Janolivermr\JwtAuthenticatable\Exceptions\JwtLimitationException;
use RuntimeException;

class JwtUserProvider implements UserProvider
{
    public function __construct(protected TokenHandler $tokenHandler)
    {
    }

    /**
     * @inheritDoc
     */
    public function retrieveById($identifier)
    {
        throw new JwtLimitationException('Retrieval by ID is not supported.');
    }

    /**
     * @inheritDoc
     */
    public function retrieveByToken($identifier, $token): Authenticatable
    {
        throw new JwtLimitationException('Retrieval by Remember token is not supported.');
    }

    /**
     * @inheritDoc
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new JwtLimitationException('Remember token update is not supported.');
    }

    /**
     * @inheritDoc
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (!array_key_exists('jwt', $credentials)) {
            throw new RuntimeException('No JWT credential provided. Check the storage_key config.');
        }
        $token = $credentials['jwt'];
        if (!is_string($token) || empty($token)) {
            throw new InvalidArgumentException('Token must be a string.');
        }

        return new JwtUser($this->tokenHandler->getClaims($token));
    }

    /**
     * @inheritDoc
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new JwtLimitationException('Validating credentials is not supported.');
    }
}
