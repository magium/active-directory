<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

$request = \Zend\Psr7Bridge\Psr7ServerRequest::fromZend(new \Zend\Http\PhpEnvironment\Request());

$factory = new \Magium\Configuration\MagiumConfigurationFactory();
$manager = $factory->getManager();
$configuration = $manager->getConfiguration();

$adapter = new \Magium\ActiveDirectory\ActiveDirectory($configuration, $request);

$entity = $adapter->authenticate();
