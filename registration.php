<?php

$repo = \Magium\Configuration\File\Configuration\ConfigurationFileRepository::getInstance();
$repo->addSecureBase(__DIR__ . DIRECTORY_SEPARATOR . 'etc');
$repo->registerConfigurationFile(
    new \Magium\Configuration\File\Configuration\XmlFile(
        __DIR__ . DIRECTORY_SEPARATOR . 'etc' . DIRECTORY_SEPARATOR . 'settings.xml'
    )
);
