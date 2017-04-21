<?php

namespace Magium\ActiveDirectory;

class Entity
{

    protected $data;

    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public function __get($name)
    {
        if (isset($this->data[$name])) {
            return $this->data[$name];
        }
        return null;
    }

    public function getAccessToken()
    {
        return $this->access_token;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getOid()
    {
        return $this->oid;
    }

    public function getPreferredUsername()
    {
        return $this->preferred_username;
    }

    public function getData()
    {
        return $this->data;
    }
}
