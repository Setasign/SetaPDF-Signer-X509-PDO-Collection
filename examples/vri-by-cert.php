<?php

use setasign\SetaPDF2\Demos\Signer\X509\Collection\PdoCollection;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Collector;

$start = microtime(true);

require_once '../vendor/autoload.php';

$path = 'sqlite:../assets/eutl+aatl.sqlite';
$version = file_get_contents('../assets/version.data');
$dbh  = new PDO($path);
$collection = new PdoCollection($dbh, $version);

$cert = Certificate::fromFile('../assets/CertExchangeJanSlabon.cer');
$collector = new Collector();
$collector->getTrustedCertificates()->add($collection);
$collector->getLogger()->setDirectOutput(true);
$vri = $collector->getByCertificate($cert);

var_dump(microtime(true) - $start);
