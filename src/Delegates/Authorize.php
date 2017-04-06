<?php

namespace Magium\ActiveDirectory\Delegates;

use League\OAuth2\Client\Provider\AbstractProvider;
use Magium\ActiveDirectory\ActiveDirectory;
use Psr\Http\Message\ResponseInterface;
use Zend\Http\Header\Location;
use Zend\Http\PhpEnvironment\Response;
use Zend\Psr7Bridge\Psr7Response;

class Authorize
{

    protected $provider;
    protected $response;

    public function __construct(
        AbstractProvider $provider,
        ResponseInterface $response = null
    )
    {
        $this->provider = $provider;
        $this->response = $response;
    }

    public function execute()
    {
        $_SESSION[ActiveDirectory::SESSION_KEY] = [];
        $authorizationUrl = $this->provider->getAuthorizationUrl();
        $_SESSION[ActiveDirectory::SESSION_KEY]['state'] = $this->provider->getState();
        $finalResponse = new Response();
        if ($this->response instanceof ResponseInterface) {
            $response = Psr7Response::toZend($this->response);
            $finalResponse->setHeaders($response->getHeaders());
        }
        $location = (new Location())->setUri($authorizationUrl);
        $finalResponse->getHeaders()->addHeader($location);
        $finalResponse->setStatusCode(302);
        $finalResponse->sendHeaders();
        // We do not send the body because it's irrelevant
        exit;
    }

}
