<?php

declare(strict_types=1);

namespace Janolivermr\JwtAuthenticatable;

use DateTimeImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use InvalidArgumentException;
use Janolivermr\JwtAuthenticatable\Exceptions\JwtLimitationException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validator;
use Psr\Clock\ClockInterface as Clock;
use RuntimeException;

class JwtUserProvider implements UserProvider
{
    protected bool $shouldValidate = true;

    public function __construct(
        protected Parser $parser,
        protected Validator $validator,
        protected SignatureManager $signatureManager
    ) {
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
        $jwt = $this->parser->parse($token);
        if (!($jwt instanceof UnencryptedToken)) {
            throw new InvalidArgumentException('Token must be an unencrypted token.');
        }

        if ($this->shouldValidate) {
            $this->validator->assert(
                $jwt,
                new Constraint\SignedWith($this->signatureManager->getSigner($jwt), $this->signatureManager->findPublicKey($jwt)),
                new Constraint\StrictValidAt($this->getClock())
            );
        }

        return new JwtUser($jwt->claims());
    }

    /**
     * @inheritDoc
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new JwtLimitationException('Validating credentials is not supported.');
    }

    public function disableValidation()
    {
        $this->shouldValidate = false;
    }

    protected function getClock(): Clock
    {
        return new class implements Clock {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };
    }
}