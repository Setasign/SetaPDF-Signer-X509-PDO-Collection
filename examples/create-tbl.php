<?php

use setasign\SetaPDF2\Signer\PemHelper;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Demos\Signer\X509\Collection\PdoCollection;

$start = microtime(true);

require_once '../vendor/autoload.php';

$path = 'sqlite:../assets/eutl-2026-02-05.sqlite';
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

//$tmpCollection = new \setasign\SetaPDF2\Signer\X509\Collection();

foreach (PemHelper::extractFromFile('../assets/eutl-2026-02-05.pem') as $key => $value) {
    try {
        $cert = new Certificate($value);
        $collection->add($cert);
//        $tmpCollection->add($cert);

    } catch (Exception $e) {
        echo $e->getMessage();
    }
}

file_put_contents('../assets/version.data', $version);

// remove outdated version
$collection->removeOtherVersions();

//
//$now = new DateTime('2002-03-16 17:20:20', new \DateTimeZone('+1'));
//$validAt = $tmpCollection->findByValidAt($now, new \DateTimeZone('+1'));
//var_dump($validAt->count());

var_dump(microtime(true) - $start);