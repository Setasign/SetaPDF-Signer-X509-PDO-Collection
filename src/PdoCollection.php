<?php

namespace setasign\SetaPDF2\Demos\Signer\X509\Collection;

use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;
use setasign\SetaPDF2\Signer\X509\Collection\FindByKeyHashInterface;
use setasign\SetaPDF2\Signer\X509\Collection\FindBySubjectKeyIdentifierInterface;
use setasign\SetaPDF2\Signer\X509\CollectionInterface;
use setasign\SetaPDF2\Signer\X509\Extension\SubjectKeyIdentifier;

class PdoCollection implements
    CollectionInterface,
    FindBySubjectKeyIdentifierInterface,
    FindByKeyHashInterface
{
    protected \PDO $pdo;
    protected string $tlVersion;
    protected array $containsCache = [];

    /**
     * @param \PDO $pdo
     * @param string $tlVersion This parameter can be used to identify a version of a trust list (e.g. if it is updated)
     */
    public function __construct(\PDO $pdo, string $tlVersion = '')
    {
        $this->pdo = $pdo;
        $this->tlVersion = $tlVersion;
    }

    public function getAll(): array
    {
        $result = [];
        $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ?');
        if ($stm->execute([$this->tlVersion]) === false) {
            return [];
        }

        foreach ($stm->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $certificate = new Certificate($row['certificate']);
            $result[$certificate->getDigest()] = $certificate;
        }

        return $result;
    }

    public function contains(Certificate $certificate): bool
    {
        $digest = $certificate->getDigest();
        $cacheKey = $digest . '|' . $this->tlVersion;
        if (isset($this->containsCache[$cacheKey])) {
            return $this->containsCache[$cacheKey];
        }

        $stm = $this->pdo->prepare('SELECT 1 FROM certificates WHERE tlVersion = ? AND digest = ?');
        if ($stm->execute([$this->tlVersion, $digest]) === false) {
            return false;
        }

        $found = $stm->fetchColumn();
        if ($found === false) {
            return $this->containsCache[$cacheKey] = false;
        }

        return $this->containsCache[$cacheKey] = (bool)$found;
    }

    public function getBySerialNumber($serialNumber): Certificate|false
    {
        $serialNumber = \strtolower($serialNumber);
        $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND serialNumber = ?');
        if ($stm->execute([$this->tlVersion, $serialNumber]) === false) {
            return false;
        }

        $certificate = $stm->fetchColumn();
        if ($certificate === false) {
            return false;
        }

        return new Certificate($certificate);
    }

    public function getBySubjectKeyIdentifier($subjectKeyIdentifier): Certificate|false
    {
        $subjectKeyIdentifier = \strtolower($subjectKeyIdentifier);
        $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND subjectKeyIdentifier = ?');
        if ($stm->execute([$this->tlVersion, $subjectKeyIdentifier]) === false) {
            return false;
        }

        $certificate = $stm->fetchColumn();
        if ($certificate === false) {
            return false;
        }

        return new Certificate($certificate);
    }

    public function findBySubjectKeyIdentifier($subjectKeyIdentifier): Collection
    {
        $result = new Collection();
        $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND subjectKeyIdentifier = ?');
        if ($stm->execute([$this->tlVersion, $subjectKeyIdentifier]) === false) {
            return $result;
        }

        foreach ($stm->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $result->add(new Certificate($row['certificate']));
        }

        return $result;
    }

    public function findBySubject($subject, $fullMatch = false): Collection
    {
        $result = new Collection();

        if ($fullMatch) {
            $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND subject = ?');
            $stm->execute([$this->tlVersion, $subject]);
        } else {
            $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND subject LIKE ?');
            $stm->execute([$this->tlVersion, '%' . $subject . '%']);
        }

        foreach ($stm->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $result->add(new Certificate($row['certificate']));
        }

        return $result;
    }

    public function findByIssuer($issuer, $fullMatch = false): Collection
    {
        $result = new Collection();

        if ($fullMatch) {
            $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND issuer = ?');
            $stm->execute([$this->tlVersion, $issuer]);
        } else {
            $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND issuer LIKE ?');
            $stm->execute([$this->tlVersion, '%' . $issuer . '%']);
        }

        foreach ($stm->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $result->add(new Certificate($row['certificate']));
        }

        return $result;
    }

    public function findByValidAt(\DateTimeInterface $dateTime, ?\DateTimeZone $timeZone = null): Collection
    {
        // $timeZone is not used because the unix timestamp is always UTC
        $time = $dateTime->getTimestamp();
        $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND validFrom <= ? AND validTo >= ?');
        $stm->execute([$this->tlVersion, $time, $time]);

        $result = new Collection();
        foreach ($stm->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $result->add(new Certificate($row['certificate']));
        }

        return $result;
    }

    public function findByKeyHash(string $keyHash): Collection
    {
        $result = new Collection();
        $stm = $this->pdo->prepare('SELECT certificate FROM certificates WHERE tlVersion = ? AND keyHash = ?');
        if ($stm->execute([$this->tlVersion, $keyHash]) === false) {
            return $result;
        }

        foreach ($stm->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $result->add(new Certificate($row['certificate']));
        }

        return $result;
    }

    public function count(): int
    {
        $stm = $this->pdo->prepare('SELECT count(*) FROM certificates WHERE tlVersion = ?');
        if ($stm->execute([$this->tlVersion]) === false) {
            return 0;
        }

        return (int)$stm->fetchColumn();
    }

    public function add(Certificate $certificate)
    {
        $keyIdentifier = '';
        $extension = $certificate->getExtensions()->get(SubjectKeyIdentifier::OID);
        if ($extension instanceof SubjectKeyIdentifier) {
            $keyIdentifier = $extension->getKeyIdentifier();
        }

        $data = [
            'tlVersion' => $this->tlVersion,
            'digest' => $certificate->getDigest(),
            'keyHash' => \sha1($certificate->getSubjectPublicKeyInfoRaw()),
            'subject' => $certificate->getSubjectName(),
            'issuer' => $certificate->getIssuerName(),
            'validFrom' => $certificate->getValidFrom(new \DateTimeZone('UTC'))->getTimestamp(),
            'validTo' => $certificate->getValidTo(new \DateTimeZone('UTC'))->getTimestamp(),
            'serialNumber' => $certificate->getSerialNumber(),
            'subjectKeyIdentifier' => $keyIdentifier,
            'certificate' => $certificate->get(),
        ];

        $this->remove($certificate);

        $stm = $this->pdo->prepare(<<<SQL
            INSERT INTO certificates 
                (tlVersion, digest, keyHash, subject, issuer, validFrom, validTo, serialNumber, subjectKeyIdentifier, certificate)
            VALUES
                (:tlVersion, :digest, :keyHash, :subject, :issuer, :validFrom, :validTo, :serialNumber, :subjectKeyIdentifier, :certificate)
        SQL);

        $stm->execute($data);
    }

    public function remove(Certificate $certificate): void
    {
        $this->pdo->prepare('DELETE FROM certificates WHERE tlVersion = ? AND digest = ?')
            ->execute([$certificate->getDigest(), $this->tlVersion]);

        $this->containsCache = [];
    }

    public function removeOtherVersions(): void
    {
        $this->pdo->prepare('DELETE FROM certificates WHERE tlVersion != ?')
            ->execute([$this->tlVersion]);

        $this->containsCache = [];
    }
}
