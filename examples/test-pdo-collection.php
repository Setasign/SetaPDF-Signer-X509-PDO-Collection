<?php

use setasign\SetaPDF2\Demos\Signer\X509\Collection\PdoCollection;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Extension\SubjectKeyIdentifier;

$start = microtime(true);

require_once '../vendor/autoload.php';

$path = 'sqlite:../assets/eutl+aatl.sqlite';
$version = file_get_contents('../assets/version.data');
$dbh  = new PDO($path);

$collection = new PdoCollection($dbh, $version);

// contains
$certificate = new Certificate(<<<CERT
-----BEGIN CERTIFICATE-----
MIIFYzCCA0ugAwIBAgIKYT/OiAAAAAAAHjANBgkqhkiG9w0BAQUFADBrMQswCQYD
VQQGEwJSTzERMA8GA1UECxMIQWxmYVNpZ24xKjAoBgNVBAoTIUFsZmFUcnVzdCBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEdMBsGA1UEAxMUQUxGQVRSVVNUIFJPT1Qg
Q0EgVjIwHhcNMTExMjA1MTgzMzU3WhcNMzExMTMwMTgzMzU3WjBrMQswCQYDVQQG
EwJSTzEpMCcGA1UEChMgQWxmYVRydXN0IENlcnRpZmljYXRpb24gU2VydmljZXMx
ETAPBgNVBAsTCEFsZmFTaWduMR4wHAYDVQQDExVBbGZhU2lnbiBRdWFsaWZpZWQg
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMtG/lCHFDIoDxjcv5
HJi6K6Lc2hU0wi4LUTv6G8dxJnJfAxiHUAF38x06AlpC/+feNDKvL7qDWL+e52/6
yu/ElNSn8Dv/aUnlUwd05I9ywIpInfGjOKFMPqhIR1CSdTLHmy7h7Pw/+uNlWgE9
d4wyohjNuq8yDQF2+5TDbRhw+Vhg692pbQMAOWz7Qk9LNXWQ36qCqcOy/P0lByCp
m7C4uoGu3es+vUqxkvkYjKJwjgveZE48T+quxZRL/4oBjynWN35uS4azf5AGUDek
U2QF8hXDudn3aD9wLOAvXP5FN69ehVaxuU7lGxbdtCr3fMo0/HDeb7z6si2A5g1o
xW5xAgMBAAGjggEHMIIBAzAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUa2SH
VWAxVbbNUQhGHR8X5M1lWz4wDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMB
Af8wTgYDVR0gBEcwRTAGBgRVHSAAMDsGDysGAQQBgqAzAAQAizABATAoMCYGCCsG
AQUFBwIBFhpodHRwOi8vYWxmYXNpZ24ucm8vZGVwb3ppdDAfBgNVHSMEGDAWgBTP
WRq99q7DDTDSIYKDo9F2FXPtLzA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vYWxm
YXNpZ24ucm8vY3JsL3F1YWxpZmllZC9hc3Jvb3R2Mi5jcmwwDQYJKoZIhvcNAQEF
BQADggIBAHXL+IGuBQ0hlFRFtHEZ2MVVTFSZhMzT0V6/0DwujTXLFaarDqQDL8N9
Fgth8/sXrX06SM8XcZuWFo6ZMburezqNtEMvMy1JIVvniBSaGKNyniZCTCjsQA5O
WotFmpdW/lTJbxbit5GgG9CnoA+sh7lV7kP06OAHwpDStUzu0s6HGky+9ShfJQi9
LcCPxcEFuZcgXyu/dv7GYYnexifCZpsJnCOtatTXii7faAIG8p/ptlaVkTa69mSs
Efq+B0ZVwZ5u5eyToVb5iAo+WTvFwmOawggkY8Ah2F57iepG8ZWvQxZkGC3P9tEw
u626iIbICSsyxyuNi93ZBXOQZukFPL9o5diEukE1o3E6SeCGDNQrEOlHO7n4LAYs
rEvpBWzND/Uzt2lggE9UctVNgG4R379EPmBVeL5O/39vtq8bcr0NsUrzxwQho4Pn
bjdghXrdTGlvkFYQewnzwUAU3KVQu7fNnEp+SJNMSw3IZ78NLt0MIR8RJVCybilL
e/gyOGjAHfCSVXDaHFzUKr5YPH21OjED8HD6ZN4ERdn82RfNYTcqZnA0fS/UUE8S
hUVxYUrUJTlxxL8epFVJyTfIiYz41/iod2iNNuAq/6p25uGh7LsoSqz0GYW2h99W
hq4tJYyO4DdUkkV2PW+rn+Q1ejwsK1oy1sIz9ZVUDImcVLS7IbsC
-----END CERTIFICATE-----
CERT);

// count
var_dump($collection->count());

var_dump($collection->contains($certificate) === true);

var_dump($collection->getBySerialNumber($certificate->getSerialNumber())->getSubjectName() === $certificate->getSubjectName());

$keyIdentifier = $certificate->getExtensions()->get(SubjectKeyIdentifier::OID)->getKeyIdentifier();
var_dump($collection->getBySubjectKeyIdentifier($keyIdentifier)->getSubjectName() === $certificate->getSubjectName());

// findBySubject
$subCollection = $collection->findBySubject($certificate->getSubjectName(), true);
var_dump($subCollection->count() === 1);

$subCollection = $collection->findBySubject('/C=RO/O=AlfaTrust Certification', false);
var_dump($subCollection->count() === 12);
//foreach ($subCollection->getAll() as $item) {
//    var_dump($item->getSubjectName());
//}

// findByIssuer
$subCollection = $collection->findByIssuer('/C=RO/OU=Cert Digital CA/O=Centrul de Calcul SA/CN=Cert Digital ROOT CA', true);
var_dump($subCollection->count() === 4);
//foreach ($subCollection->getAll() as $item) {
//    var_dump($item->getIssuerName());
//}

$subCollection = $collection->findByIssuer('/C=RO/O=ALFATRUST CERTIFICATION', false);
var_dump($subCollection->count() === 10);
//foreach ($subCollection->getAll() as $item) {
//    var_dump($item->getIssuerName());
//}

// findByValidAt
$now = new DateTime('2002-03-16 00:01:00');
$validAt = $collection->findByValidAt($now);
var_dump($validAt->count() == 87);
//foreach ($subCollection->getAll() as $item) {
//    var_dump($item->getIssuerName());
//}

// getAll()
//var_dump(count($collection->getAll()));

var_dump(microtime(true) - $start);