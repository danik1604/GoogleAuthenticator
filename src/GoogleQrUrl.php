<?php

namespace Sonata\GoogleAuthenticator;

class GoogleQrUrl
{
    private function __construct()
    {

    }

    public static function generate(string $accountName, string $secret, ?string $issuer = null, int $size = 200): string
    {
        if ('' === $accountName || false !== strpos($accountName, ':')) {
            throw RuntimeException::InvalidAccountName($accountName);
        }

        if ('' === $secret) {
            throw RuntimeException::InvalidSecret();
        }

        $label = $accountName;
        $otpauthString = 'otpauth://totp/%s?secret=%s';

        if (null !== $issuer) {
            if ('' === $issuer || false !== strpos($issuer, ':')) {
                throw RuntimeException::InvalidIssuer($issuer);
            }

            $label = $issuer.':'.$label;
            $otpauthString .= '&issuer=%s';
        }

        $otpauthString = urlencode(sprintf($otpauthString, $label, $secret, $issuer));

        return sprintf(
            'https://chart.googleapis.com/chart?chs=%1$dx%1$d&cht=qr&chl=%2$s&ecc=M',
            $size,
            $otpauthString
        );
    }

}