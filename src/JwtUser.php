<?php

declare(strict_types=1);

namespace Janolivermr\JwtAuthenticatable;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Arr;
use Janolivermr\JwtAuthenticatable\Exceptions\JwtLimitationException;

class JwtUser implements Authenticatable
{
    public function __construct(protected array $claims)
    {
    }

    /**
     * @inheritDoc
     */
    public function getAuthIdentifierName(): string
    {
        return 'sub';
    }

    /**
     * @inheritDoc
     */
    public function getAuthIdentifier()
    {
        return $this->{$this->getAuthIdentifierName()};
    }

    /**
     * @inheritDoc
     */
    public function getAuthPassword(): string
    {
        throw new JwtLimitationException('Auth Password does not exist.');
    }

    /**
     * @inheritDoc
     */
    public function getRememberToken(): string
    {
        throw new JwtLimitationException('Remember Token does not exist.');
    }

    /**
     * @inheritDoc
     */
    public function setRememberToken($value): void
    {
        throw new JwtLimitationException('Remember Token does not exist.');
    }

    /**
     * @inheritDoc
     */
    public function getRememberTokenName(): string
    {
        throw new JwtLimitationException('Remember Token does not exist.');
    }

    public function __get(string $name)
    {
        return Arr::get($this->claims, $name);
    }

    public function __isset(string $name): bool
    {
        return Arr::has($this->claims, $name);
    }
}
