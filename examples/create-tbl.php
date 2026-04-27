<?php

use GuzzleHttp\Client;
use setasign\SetaPDF2\Signer\PemHelper;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Demos\Signer\X509\Collection\PdoCollection;
use setasign\SetaPDF2\Signer\X509\Collection;
use setasign\TrustListFetcher\Aatl;
use setasign\TrustListFetcher\Eutl;

$start = microtime(true);

require_once '../vendor/autoload.php';

$path = 'sqlite:../assets/eutl+aatl.sqlite';
$dbh  = new PDO($path);

$query[] = <<<SQL
create table if not exists certificates  
(
    tlVersion            TEXT,
    digest               TEXT,
    keyHash              TEXT,
    subject              TEXT,
    issuer               TEXT,
    validFrom            INTEGER,
    validTo              INTEGER,
    serialNumber         TEXT,
    subjectKeyIdentifier TEXT,
    certificate          TEXT,
    constraint certificates_pk
        primary key (digest, tlVersion)
);
SQL;

$query[] = <<<SQL
create index if not exists certificates_issuer_index
    on certificates (issuer, tlVersion);
SQL;

$query[] = <<<SQL
create index if not exists certificates_keyHash_index
    on certificates (keyHash, tlVersion);
SQL;

$query[] = <<<SQL
create index if not exists certificates_subjectKeyIdentifier_index
    on certificates (subjectKeyIdentifier, tlVersion);
SQL;

$query[] = <<<SQL
create index if not exists certificates_subject_index
    on certificates (subject, tlVersion);
SQL;

$query[] = <<<SQL
create index if not exists certificates_tlVersion_index
    on certificates (tlVersion);
SQL;

foreach ($query as $item) {
    var_dump($dbh->exec($item));
}

$version = time();
$collection = new PdoCollection($dbh, $version);

var_dump($collection->count());
//die();

// AATL
$trustedCerts = new Collection();
$trustedCerts->addFromFile(__DIR__ . '/../vendor/setasign/trust-list-fetcher/assets/Adobe Root CA G2.cer');
$trustedCerts->addFromFile(__DIR__ . '/../vendor/setasign/trust-list-fetcher/assets/DigiCert Trusted Root G4.cer');

$client = new Client([
    'verify' => __DIR__ . '/../vendor/setasign/trust-list-fetcher/assets/cacert-2026-04-16+interm-for-IE.pem'
]);

$start = microtime(true);

$aatlFetcher = new Aatl($client, $trustedCerts);
$aatlFetcher->getLogger()->setDirectOutput(true);

$passed = $faulty = 0;
try {
    $aatlFetcher->fetch(
        function (Certificate $certificate) use (&$collection, &$passed) {
            $collection->add($certificate);
            $passed++;
        },

        function (\InvalidArgumentException $e, string $certificate) use (&$faulty) {
            $faulty++;
            var_dump('ERROR', $e->getMessage(), $certificate);
        }
    );

    var_dump($passed, $faulty);
} catch (Exception $e) {
    var_dump($e->getMessage());

    $dbh->prepare('DELETE FROM certificates WHERE tlVersion = ?')
        ->execute([$version]);
    die();
}


// EUTL
$trustedCerts = new Collection();
$trustedCerts->add(PemHelper::extractFromFile(__DIR__ . '/../vendor/setasign/trust-list-fetcher/assets/LOTL-signing-certificates-2026-04-15.pem'));

$eutlFetcher = new Eutl($client, $trustedCerts);
$eutlFetcher->getLogger()->setDirectOutput(true);

$passed = $faulty = 0;
try {
    $eutlFetcher->fetch(
        function (Certificate $certificate) use (&$collection, &$passed) {
            $collection->add($certificate);
            $passed++;
        },

        function (\InvalidArgumentException $e, string $certificate) use (&$faulty) {
            $faulty++;
            var_dump('ERROR', $e->getMessage(), $certificate);
        }
    );

    var_dump($passed, $faulty);
} catch (Exception $e) {
    var_dump($e->getMessage());

    $dbh->prepare('DELETE FROM certificates WHERE tlVersion = ?')
        ->execute([$version]);
    die();
}


file_put_contents('../assets/version.data', $version);

// remove outdated version
$collection->removeOtherVersions();

//
//$now = new DateTime('2002-03-16 17:20:20', new \DateTimeZone('+1'));
//$validAt = $tmpCollection->findByValidAt($now, new \DateTimeZone('+1'));
//var_dump($validAt->count());

var_dump(microtime(true) - $start);