<?php

namespace Magium\ActiveDirectory;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericProvider;
use Magium\ActiveDirectory\Delegates\Authorize;
use Magium\ActiveDirectory\Delegates\Receive;
use Magium\Configuration\Config\Repository\ConfigInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Http\Header\Location;
use Zend\Http\PhpEnvironment\Response;
use Zend\Psr7Bridge\Psr7Response;
use Zend\Uri\Uri;

class ActiveDirectory
{

    const CONFIG_CLIENT_ID      = 'magium/ad/client_id';
    const CONFIG_CLIENT_SECRET  = 'magium/ad/client_secret';
    const CONFIG_ENABLED        = 'magium/ad/enabled';
    const CONFIG_REMAP_HTTPS    = 'magium/ad/remap_https';

    const SESSION_KEY = '__MAGIUM_AD';

    protected $config;
    protected $returnUrl;
    protected $request;
    protected $response;
    protected $scopes;
    protected $endpointConfig;
    protected $oauthProvider;

    public function __construct(
        ConfigInterface $config,
        ServerRequestInterface $request,
        $returnUrl = null,
        $scopes = 'profile openid email offline_access User.Read',
        ResponseInterface $response = null,
        AbstractProvider $oauthProvider = null,
        EndpointConfig $endpointConfig = null
    )
    {
        $this->config = $config;
        $this->request = $request;
        $this->returnUrl = $returnUrl;
        $this->scopes = $scopes;
        $this->response = $response;
        $this->oauthProvider = $oauthProvider;
        $this->endpointConfig = $endpointConfig;
    }

    public function getProvider()
    {
        if (!$this->oauthProvider instanceof AbstractProvider) {
            $endPointConfig = $this->getEndpointConfig();
            $this->oauthProvider = new GenericProvider([
                'clientId' => $this->config->getValue(self::CONFIG_CLIENT_ID),
                'clientSecret' => $this->config->getValue(self::CONFIG_CLIENT_SECRET),
                'redirectUri' => $this->getReturnUrl($this->request),
                'urlAuthorize' => $endPointConfig->getAuthorityUrl() . $endPointConfig->getAuthorizeEndpoint(),
                'urlAccessToken' => $endPointConfig->getAuthorityUrl() . $endPointConfig->getTokenEndpoint(),
                'urlResourceOwnerDetails' => '',
                'scopes' => $this->scopes
            ]);
        }
        return $this->oauthProvider;
    }

    public function getRequest()
    {
        return $this->request;
    }

    public function isEnabled()
    {
        return $this->config->getValueFlag(self::CONFIG_ENABLED);
    }

    public function forget()
    {
        if (isset($_SESSION[self::SESSION_KEY])) {
            unset($_SESSION[self::SESSION_KEY]);
        }
    }

    public function getResponse()
    {
        return $this->response;
    }

    public function authenticate()
    {
        if (!$this->isEnabled()) {
            throw new InvalidRequestException('Do not authenticate if the Active Directory integration is not enabled');
        }
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new InvalidRequestException('The PHP session must be started prior to authenticating');
        }

        if (isset($_SESSION[self::SESSION_KEY]['entity'])) {
            return $_SESSION[self::SESSION_KEY]['entity'];
        }

        $request = $this->getRequest();
        $params = $request->getQueryParams();

        if ($request->getMethod() == 'GET' && isset($params['error'])) {
            throw new ClientException($params['error_description']);
        } else if ($request->getMethod() == 'GET' && !isset($params['code'])) {
            (new Authorize($this->getProvider(), $this->getResponse()))->execute();
        } else if ($request->getMethod() == 'GET' && isset($params['code'])) {
            return (new Receive($this->getRequest(), $this->getProvider()))->execute();
        }
        throw new InvalidRequestException('Could not understand the request');
    }

    public function setReturnUrl($url)
    {
        $this->returnUrl = (string)$url;
    }

    public function getReturnUrl(ServerRequestInterface $request)
    {
        if ($this->returnUrl === null) {
            $this->returnUrl = $this->getDefaultReturnUrl($request);
        }
        return $this->returnUrl;
    }

    public function getEndpointConfig()
    {
        if (!$this->endpointConfig instanceof EndpointConfig) {
            $this->endpointConfig = new EndpointConfig();
        }
        return $this->endpointConfig;
    }

    public function getDefaultReturnUrl(ServerRequestInterface $request)
    {
        $uri = new Uri();
        if ($request->getUri()->getHost() != 'localhost'
            && $this->config->getValueFlag(self::CONFIG_REMAP_HTTPS)) {
            $uri->setScheme('https');
        } else {
            $uri->setScheme($request->getUri()->getScheme());
        }
        $uri->setHost($request->getUri()->getHost());
        $uri->setPath($request->getUri()->getPath());
        $uri->setPort($request->getUri()->getPort());
        return $uri->toString();
    }

}
