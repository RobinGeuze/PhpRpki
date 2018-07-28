<?php

require __DIR__ . '/../vendor/autoload.php';

use RobinGeuze\PhpRpki\Repository;

$rpkiSources = [
    'arin' => [
        'trust-anchor' => 'rsync://rpki.arin.net/repository/arin-rpki-ta.cer',
        'repository-primers' => [],
    ],
    'afrinic' => [
        'trust-anchor' => 'rsync://rpki.afrinic.net/repository/AfriNIC.cer',
        'repository-primers' => [
            'rsync://rpki.afrinic.net/repository/',
        ],
    ],
    'apnic' => [
        'trust-anchor' => 'rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer',
        'repository-primers' => [
            'rsync://rpki.apnic.net/member_repository/',
            'rsync://rpki.apnic.net/repository/',
            'rsync://rpki-repository.nic.ad.jp/ap/',
        ],
    ],
    'lacnic' => [
        'trust-anchor' => 'rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer',
        'repository-primers' => [],
    ],
    'ripe' => [
        'trust-anchor' => 'rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer',
        'repository-primers' => [],
    ],
];

$tempDir = sys_get_temp_dir();

$rpkiBaseDir = $tempDir . '/rpki/';
if (!is_dir($rpkiBaseDir)) {
    mkdir($rpkiBaseDir);
}

$ips = [];
foreach ($rpkiSources as $rir => $source) {
    $rirBaseDir = "{$rpkiBaseDir}{$rir}/";

    if (!is_dir($rirBaseDir)) {
        mkdir($rirBaseDir);
    }

    $repo = new Repository($source['trust-anchor'], $rirBaseDir, $source['repository-primers']);
    $repoIps = $repo->parseRepository();

    foreach ($repoIps as $ip => $values) {
        if (!isset($ips[$ip])) {
            $ips[$ip] = $values;
            continue;
        }
        $ips[$ip] = array_merge($ips[$ip], $values);
    }
}

echo json_encode($ips, JSON_PRETTY_PRINT);
