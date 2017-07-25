<?php

require_once __DIR__ . '/../../vendor/autoload.php';

session_start();

$config = [
    'authentication' => [
        'ad' => [
            'client_id' => '0d629fa2-f1d7-446c-a5ec-88aecbcc2801',
            'client_secret' => 'uQkhr2W6iYtiBCrkD8yhw0A',
            'enabled' => '1',
            'directory' => '74d24007-d458-483a-9d96-de05952da2d8'
        ]
    ]
];

$request = new \Zend\Http\PhpEnvironment\Request();

$ad = new \Magium\ActiveDirectory\ActiveDirectory(
    new \Magium\Configuration\Config\Repository\ArrayConfigurationRepository($config),
    Zend\Psr7Bridge\Psr7ServerRequest::fromZend(new \Zend\Http\PhpEnvironment\Request())
);

$entity = $ad->authenticate();

echo $entity->getName() . '<Br />';
echo $entity->getOid() . '<Br />';
echo $entity->getPreferredUsername() . '<Br />';
