<?php

declare(strict_types=1);

namespace Janolivermr\JwtAuthenticatable;

use Illuminate\Contracts\Auth\Authenticatable;
use Janolivermr\JwtAuthenticatable\Exceptions\JwtLimitationException;
use Lcobucci\JWT\Token\DataSet;

class JwtUser implements Authenticatable
{
    public function __construct(protected DataSet $claims)
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
        return $this->claims->get($name);
    }

    public function __isset(string $name): bool
    {
        return $this->claims->has($name);
    }
}
