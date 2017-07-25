<?php

namespace Magium\ActiveDirectory;

class EndpointConfig
{

    protected $authorityUrl;
    protected $authorizeEndpoint;
    protected $application;
    protected $tokenEndpoint;
    protected $resourceId;

    public function __construct(
        $application = 'common',
        $authorityUrl = 'https://login.microsoftonline.com/',
        $authorizeEndpoint = '/oauth2/v2.0/authorize',
        $tokenEndpoint = '/oauth2/v2.0/token',
        $resourceId = 'https://graph.microsoft.com'
        )
    {
        $this->authorityUrl = $authorityUrl;
        $this->application = $application;
        $this->authorizeEndpoint = $authorizeEndpoint;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->resourceId = $resourceId;
    }

    /**
     * @return string
     */
    public function getAuthorityUrl()
    {
        return $this->authorityUrl . $this->application;
    }

    /**
     * @return string
     */
    public function getAuthorizeEndpoint()
    {
        return $this->authorizeEndpoint;
    }

    /**
     * @return string
     */
    public function getTokenEndpoint()
    {
        return $this->tokenEndpoint;
    }

    /**
     * @return string
     */
    public function getResourceId()
    {
        return $this->resourceId;
    }

}
