<?php

require_once __DIR__ . '/../../vendor/autoload.php';

session_start();

$config = [
    'authentication' => [
        'ad' => [
            'client_id' => '',
            'client_secret' => '',
            'enabled' => '1',
            'directory' => ''
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
