<?php

declare(strict_types=1);

namespace Janolivermr\JwtAuthenticatable;

interface TokenHandler
{
    /**
     * @param string $token
     * @return array<string, mixed>
     */
    public function getClaims(string $token): array;
}
