<?php

namespace RobinGeuze\PhpRpki;

use vakata\asn1\ASN1;

class Repository
{
    private $repositoryBaseUrls = [];
    private $taUrl;
    private $tempDir;

    private $certs = [];
    private $ips = [];

    public function __construct($taUrl, $tempDir, $repositoryPrimers)
    {
        $this->taUrl = $taUrl;
        $this->tempDir = $tempDir;

        foreach ($repositoryPrimers as $repositoryPrimer) {
            $this->ensureRsyncUrl($repositoryPrimer, false);
        }
    }

    private function ensureRsyncUrl($url, $file)
    {
        $found = false;
        $baseDir = '';
        $suffix = '';
        foreach ($this->repositoryBaseUrls as $baseUrl => $directory) {
            if (strpos($url, $baseUrl) === 0) {
                $baseDir = $directory;
                $suffix = substr($url, strlen($baseUrl));
                $found = true;
                break;
            }
        }

        if ($found) {
            return $baseDir . $suffix;
        }

        if ($file) {
            $output = [];
            $returnValue = null;
            exec("rsync {$url} {$this->tempDir}", $output, $returnValue);
            if ($returnValue !== 0) {
                return null;
            }
            return $this->tempDir . basename($url);
        }

        $basename = basename($url);

        $directory = $this->tempDir . $basename . '/';

        $output = [];
        $returnValue = null;
        exec("rsync -r {$url} {$directory}", $output, $returnValue);
        if ($returnValue !== 0) {
            return null;
        }

        $this->repositoryBaseUrls[$url] = $directory;

        return $directory;
    }

    private function handleRoa($roaFile, $cert)
    {
        $dir = dirname($roaFile);

        $caFile = $dir . '/ca.pem';

        file_put_contents($caFile, $this->certs[$cert]);

        $descriptorSpec = [
            0 => STDIN,
            1 => [ 'pipe', 'w' ],
            2 => [ 'file', '/dev/null', 'a' ],
        ];

        $pipes = [];
        $handle = proc_open("openssl cms -verify -in {$roaFile} -CAfile {$caFile} -inform DER", $descriptorSpec, $pipes);
        $roaData = stream_get_contents($pipes[1]);
        proc_close($handle);

        $roaTemplate = [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'asId' => [
                    'tag' => ASN1::TYPE_INTEGER,
                ],
                'ipAddrBlocks' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'repeat' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'children' => [
                            'addressFamily' => [
                                'tag' => ASN1::TYPE_OCTET_STRING,
                            ],
                            'addresses' => [
                                'tag' => ASN1::TYPE_SEQUENCE,
                                'repeat' => [
                                    'tag' => ASN1::TYPE_SEQUENCE,
                                    'children' => [
                                        'address' => [
                                            'tag' => ASN1::TYPE_BIT_STRING,
                                        ],
                                        'maxLength' => [
                                            'tag' => ASN1::TYPE_INTEGER,
                                            'optional' => true,
                                        ],
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];

        $parsedData = ASN1::decodeDER($roaData, $roaTemplate);
        foreach ($parsedData['ipAddrBlocks'] as $addrBlocks) {
            $addressFamily = bin2hex(base64_decode($addrBlocks['addressFamily']));
            switch ($addressFamily) {
                case '0001':
                    $addressFamily = 4;
                    break;

                case '0002':
                    $addressFamily = 6;
                    break;
            }
            foreach ($addrBlocks['addresses'] as $addrBlock) {
                $unusedBits = ord($addrBlock['address'][0]);
                $prefix = substr($addrBlock['address'], 1);
                $netmask = strlen($prefix)  * 8 - $unusedBits;
                switch ($addressFamily) {
                    case 4:
                        $prefix = str_pad($prefix, 4, chr(0));
                        $block['maxLength'] = 32;
                        break;

                    case 6:
                        $prefix = str_pad($prefix, 16, chr(0));
                        $block['maxLength'] = 128;
                        break;
                }
                $ip = inet_ntop($prefix) . '/' . $netmask;

                $as = $parsedData['asId'];

                if (isset($addrBlock['maxLength'])) {
                    $as .= ':' . $addrBlock['maxLength'];
                }
                if (!isset($this->ips[$ip])) {
                    $this->ips[$ip] = [];
                }
                $this->ips[$ip][] = $as;
            }
        }
    }

    private function handleManifest($url, $cert)
    {
        $manifestFile = $this->ensureRsyncUrl($url, true);

        if ($manifestFile === null) {
            fprintf(STDERR, "Manifest %s not available, skipping\n", $url);
            return;
        }

        $dir = dirname($manifestFile);

        $caFile = $dir . '/ca.pem';

        file_put_contents($caFile, $this->certs[$cert]);

        $descriptorSpec = [
            0 => STDIN,
            1 => [ 'pipe', 'w' ],
            2 => [ 'file', '/dev/null', 'a' ],
        ];

        $pipes = [];
        $handle = proc_open("openssl cms -verify -in {$manifestFile} -CAfile {$caFile} -inform DER", $descriptorSpec, $pipes);
        $manifestData = stream_get_contents($pipes[1]);
        proc_close($handle);

        $manifestTemplate = [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'manifestNumber' => [
                    'tag' => ASN1::TYPE_INTEGER,
                ],
                'thisUpdate' => [
                    'tag' => ASN1::TYPE_GENERALIZED_TIME,
                ],
                'nextUpdate' => [
                    'tag' => ASN1::TYPE_GENERALIZED_TIME,
                ],
                'fileHashAlg' => [
                    'tag' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'fileList' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'repeat' => [
                        'tag' => ASN1::TYPE_SEQUENCE,
                        'children' => [
                            'file' => [
                                'tag' => ASN1::TYPE_IA5_STRING,
                            ],
                            'hash' => [
                                'tag' => ASN1::TYPE_BIT_STRING,
                            ],
                        ],
                    ],
                ],
            ],
        ];

        $parsedData = ASN1::decodeDER($manifestData, $manifestTemplate);
        foreach ($parsedData['fileList'] as $fileData) {
            if (substr(bin2hex($fileData['hash']), 2) !== hash_file($parsedData['fileHashAlg'], $dir . '/' . $fileData['file'])) {
                fprintf(STDERR, "Hash for file %s/%s invalid, skipping this manifest!\n", $dir, $fileData['file']);
                return;
            }
        }

        foreach ($parsedData['fileList'] as $fileData) {
            if (preg_match('#.*\\.crl#', $fileData['file'])) {
                $beginpem = "-----BEGIN X509 CRL-----\n";
                $endpem = "-----END X509 CRL-----\n";
                $pemData = $beginpem . chunk_split(base64_encode(file_get_contents($dir . '/' . $fileData['file'])), 76, "\n") . $endpem;
                $this->certs[$cert] = $pemData . $this->certs[$cert];
            }
        }

        foreach ($parsedData['fileList'] as $fileData) {
            if (preg_match('#.*\\.cer#', $fileData['file'])) {
                $this->handleCertificate($dir . '/' . $fileData['file']);
            }
        }

        foreach ($parsedData['fileList'] as $fileData) {
            if (preg_match('#.*\\.roa#', $fileData['file'])) {
                $this->handleRoa($dir . '/' . $fileData['file'], $cert);
            }
        }
    }

    private function handleCertificate($certFile)
    {
        $beginpem = "-----BEGIN CERTIFICATE-----\n";
        $endpem = "-----END CERTIFICATE-----\n";

        $pemData = $beginpem . chunk_split(base64_encode(file_get_contents($certFile)), 76, "\n") . $endpem;

        $handle = openssl_x509_read($pemData);

        $certData = openssl_x509_parse($handle);

        $subjectKeyIdentifier = $certData['extensions']['subjectKeyIdentifier'];

        if (isset($certData['extensions']['authorityKeyIdentifier'])) {
            $matches = [];
            if (!preg_match('/^keyid:(.*)$/', $certData['extensions']['authorityKeyIdentifier'], $matches)) {
                echo "Invalid authority key identifier\n";
                exit(0);
            }
            $authorityKeyIdentifier = $matches[1];

            if ($authorityKeyIdentifier !== $subjectKeyIdentifier) {
                if (!isset($this->certs[$authorityKeyIdentifier])) {
                    echo "Missing authority cert\n";
                    exit(0);
                }
                $pemData .= $this->certs[$authorityKeyIdentifier];
            }
        }

        $this->certs[$subjectKeyIdentifier] = $pemData;

        $subjectInfoAccess = $certData['extensions']['subjectInfoAccess'];

        $matches = [];
        if (preg_match('#CA Repository - URI:(rsync://.*)#', $subjectInfoAccess, $matches)) {
            $repository = $matches[1];

            $result = $this->ensureRsyncUrl($repository, false);
            if ($result === null) {
                fprintf(STDERR, "Repository for %s not available, skipping\n", $certFile);
                return;
            }
        }

        $matches = [];
        if (preg_match('#1.3.6.1.5.5.7.48.10 - URI:(rsync://.*)#', $subjectInfoAccess, $matches)) {
            $manifest = $matches[1];

            $this->handleManifest($manifest, $subjectKeyIdentifier);
        }
    }

    public function parseRepository()
    {
        $certFile = $this->ensureRsyncUrl($this->taUrl, true);
        $this->handleCertificate($certFile);

        return $this->ips;
    }
}