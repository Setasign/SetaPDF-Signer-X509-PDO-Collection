<?php

use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Signer\DocumentSecurityStore;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Collector;
use setasign\SetaPDF2\Demos\Signer\X509\Collection\PdoCollection;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\IntegrityResult;

require_once '../vendor/autoload.php';

$start = microtime(true);

$pdfPath = '../assets/sample_pdf.pdf';
//$pdfPath = '../assets/Laboratory-Report-signed.pdf';
//$pdfPath = '../assets/qualified-timestamp-datasure.pdf';
//$pdfPath = '../assets/qualified-timestamp-globaltrust.pdf';

$path = 'sqlite:../assets/eutl+aatl.sqlite';
$version = file_get_contents('../assets/version.data');
$dbh  = new PDO($path);

$collection = new PdoCollection($dbh, $version);

$writer = new FileWriter('add-ltv.pdf');
$document = Document::loadByFilename($pdfPath, $writer);

$collector = new Collector();
$collector->setAllowTrustedIntermediateCertificatesAsTrustAnchor(true);

$trustedCerts = $collector->getTrustedCertificates();
$trustedCerts->add($collection);

$logger = $collector->getLogger();
$logger->setDirectOutput(true);

$signatureFieldNames = Signer::getSignatureFieldNames($document);

$dss = new DocumentSecurityStore($document);
//$dss->setOptimizeOcspResponses(false);

foreach ($signatureFieldNames as $fieldName) {
    $integrityResult = IntegrityResult::create($document, $fieldName);

    if ($integrityResult->getStatus() === IntegrityResult::STATUS_NOT_SIGNED) {
        printf("Field (%s) is not signed.\n", $fieldName);
        continue;
    }

    $vri = $collector->getByIntegrityResult($integrityResult);
    $dss->addValidationRelatedInfoResultByField($fieldName, $vri);
    // THIS IS REALLY ONLY NEEDED FOR ACROBAT!!
    foreach ($vri->getOcspResponses() as $ocspResponse) {
        $key = $dss->getVriName($ocspResponse);
        $dss->addValidationRelatedInfo($key, [], [], [], new DateTime());
    }
}

$document->save()->finish();

var_dump(microtime(true) - $start);