<?php

namespace GoogleAuthenticator;

class Google
{

    private $passCodeLength;
    private $secretLength;
    private $pinModulo;
    private $instanceTime;
    private $codePeriod;
    private $periodSize = 30;

    public function __construct(int $passCodeLength = 6, int $secretLength = 10, ?\DateTimeInterface $instanceTime = null, int $codePeriod = 30)
    {
        $this->passCodeLength = $passCodeLength;
        $this->secretLength = $secretLength;
        $this->codePeriod = $codePeriod;
        $this->periodSize = $codePeriod < $this->periodSize ? $codePeriod : $this->periodSize;
        $this->pinModulo = 10 ** $passCodeLength;
        $this->instanceTime = $instanceTime ?? new \DateTimeImmutable();
    }

    public function checkCode($secret, $code, $discrepancy = 1): bool
    {
        $periods = floor($this->codePeriod / $this->periodSize);

        $result = 0;
        for ($i = -$discrepancy; $i < $periods + $discrepancy; ++$i) {
            $dateTime = new \DateTimeImmutable('@'.($this->instanceTime->getTimestamp() - ($i * $this->periodSize)));
            $result = hash_equals($this->getCode($secret, $dateTime), $code) ? $dateTime->getTimestamp() : $result;
        }

        return $result > 0;
    }

    public function getCode($secret, $time = null): string
    {
        if (null === $time) {
            $time = $this->instanceTime;
        }

        if ($time instanceof \DateTimeInterface) {
            $timeForCode = floor($time->getTimestamp() / $this->periodSize);
        } else {
            @trigger_error(
                'Passing anything other than null or a DateTimeInterface to $time is deprecated as of 2.0 '.
                'and will not be possible as of 3.0.',
                \E_USER_DEPRECATED
            );
            $timeForCode = $time;
        }

        $base32 = new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true);
        $secret = $base32->decode($secret);

        $timeForCode = str_pad(pack('N', $timeForCode), 8, \chr(0), \STR_PAD_LEFT);

        $hash = hash_hmac('sha1', $timeForCode, $secret, true);
        $offset = \ord(substr($hash, -1));
        $offset &= 0xF;

        $truncatedHash = $this->hashToInt($hash, $offset) & 0x7FFFFFFF;

        return str_pad((string) ($truncatedHash % $this->pinModulo), $this->passCodeLength, '0', \STR_PAD_LEFT);
    }

    public function getUrl($user, $hostname, $secret): string
    {
        $issuer = \func_get_args()[3] ?? null;
        $accountName = sprintf('%s@%s', $user, $hostname);
        $url = GoogleQrUrl::generate($accountName, $secret);
        if ($issuer) {
            $url .= '%26issuer%3D'.$issuer;
        }
        return $url;
    }

    public function generateSecret(): string
    {
        return (new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true))->encode(random_bytes($this->secretLength));
    }

    private function hashToInt(string $bytes, int $start): int
    {
        return unpack('N', substr(substr($bytes, $start), 0, 4))[1];
    }

}