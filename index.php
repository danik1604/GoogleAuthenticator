<?php

include('./vendor/autoload.php');

$google = new \Sonata\GoogleAuthenticator\GoogleAuthenticator;
$secret = $google->generateSecret();
$qrCode = \Sonata\GoogleAuthenticator\GoogleQrUrl::generate('111121212', $secret, 'gos1');
var_dump($qrCode);