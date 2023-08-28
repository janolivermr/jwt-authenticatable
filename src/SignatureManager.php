<?php

declare(strict_types=1);

namespace Janolivermr\JwtAuthenticatable;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;

interface SignatureManager
{
    public function findPublicKey(Token $token): Key;

    public function getSigner(Token $token): Signer;
}