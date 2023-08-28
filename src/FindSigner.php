<?php

declare(strict_types=1);

namespace Janolivermr\JwtAuthenticatable;

use InvalidArgumentException;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;

trait FindSigner
{
    /**
     * @param Token $token
     * @param Signer[] $signers
     * @return Signer
     */
    public function findSigner(Token $token, array $signers): Signer
    {
        $alg = $token->headers()->get('alg');
        if (!is_string($alg)) {
            throw new InvalidArgumentException('Token must have an "alg" header of type "string".');
        }
        $signer = collect($signers)->mapWithKeys(function (Signer $signer) {
            return [$signer->algorithmId() => $signer];
        })->get($alg);
        if (!($signer instanceof Signer)) {
            throw new InvalidArgumentException(sprintf('Algorithm "%s" is not supported.', $alg));
        }
        return $signer;
    }
}