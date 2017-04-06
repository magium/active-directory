<?php

namespace Magium\ActiveDirectory\Delegates;

use League\OAuth2\Client\Provider\AbstractProvider;
use Magium\ActiveDirectory\ActiveDirectory;
use Magium\ActiveDirectory\Entity;
use Magium\ActiveDirectory\InvalidRequestException;
use Psr\Http\Message\ServerRequestInterface;

class Receive
{

    protected $provider;
    protected $request;

    public function __construct(
        ServerRequestInterface $request,
        AbstractProvider $provider
    )
    {
        $this->request = $request;
        $this->provider = $provider;
    }


    public function execute()
    {
        $params = $this->request->getQueryParams();
        if (
            !isset($_SESSION[ActiveDirectory::SESSION_KEY]['state'])
            || empty($params['state'])
            || ($params['state'] !== $_SESSION[ActiveDirectory::SESSION_KEY]['state'])
        ) {
            unset($_SESSION[ActiveDirectory::SESSION_KEY]);
            throw new InvalidRequestException('Request state did not match');
        }
        // Get an access token using the authorization code grant
        $accessToken = $this->provider->getAccessToken('authorization_code', [
            'code' => $params['code']
        ]);

        // The id token is a JWT token that contains information about the user
        // It's a base64 coded string that has a header, payload and signature
        $idToken = $accessToken->getValues()['id_token'];
        $decodedAccessTokenPayload = base64_decode(
            explode('.', $idToken)[1]
        );
        $jsonAccessTokenPayload = json_decode($decodedAccessTokenPayload, true);

        $data = $jsonAccessTokenPayload;
        $data['access_token'] = $accessToken->getToken();
        $entity = new Entity($data);
        return $entity;
    }

}
