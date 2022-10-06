<?php

namespace Vdhruv\Shopify;

use GuzzleHttp\Client;
use Vdhruv\Shopify\Exceptions\ShopifyApiException;
use Vdhruv\Shopify\Exceptions\ShopifyApiResourceNotFoundException;

class Shopify
{
    protected $key;
    protected $secret;
    protected string $shopDomain;
    protected string $accessToken;
    protected array $requestHeaders = [];
    protected array $responseHeaders = [];
    protected Client $client;
    protected int $responseStatusCode;
    protected string $reasonPhrase;
    private static string $ACCESS_TOKEN_URL = 'admin/oauth/access_token';

    public function __construct(Client $client)
    {
        $this->client = $client;
        $this->key = config('shopify.key');
        $this->secret = config('shopify.secret');
    }

    /**
     * @param string $shopUrl
     * @return $this
     */
    public function setShopUrl(string $shopUrl)
    {
        $url = parse_url($shopUrl);
        $this->shopDomain = $url['host'] ?? $this->removeProtocol($shopUrl);

        return $this;
    }

    /**
     * @return string
     */
    private function baseUrl(): string
    {
        return "https://{$this->shopDomain}/";
    }

    /**
     * Get the URL required to request authorization
     *
     * @param bool $scope
     * @param string $redirect_url
     * @param string $nonce
     * @return string
     */
    public function getAuthorizeUrl(bool $scope = [] || '', string $redirect_url = '', string $nonce = ''): string
    {
        if (is_array($scope)) {
            $scope = implode(",", $scope);
        }

        $url = "https://{$this->shopDomain}/admin/oauth/authorize?client_id={$this->key}&scope=" . urlencode($scope);

        if ($redirect_url != '') {
            $url .= "&redirect_uri=" . urlencode($redirect_url);
        }

        if ($nonce != '') {
            $url .= "&state=" . urlencode($nonce);
        }

        return $url;
    }

    /**
     * @param $code
     * @return mixed|null
     * @throws ShopifyApiException
     * @throws ShopifyApiResourceNotFoundException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAccessToken($code)
    {
        return $this->makeRequest(
            'POST',
            self::$ACCESS_TOKEN_URL,
            ["client_id" => $this->key, 'client_secret' => $this->secret, 'code' => $code]
        );
    }

    public function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }

    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * @return string[]
     */
    private function setXShopifyAccessToken()
    {
        return ['X-Shopify-Access-Token' => $this->accessToken];
    }

    public function addHeader($key, $value)
    {
        $this->requestHeaders = array_merge($this->requestHeaders, [$key => $value]);

        return $this;
    }

    public function removeHeaders()
    {
        $this->requestHeaders = [];

        return $this;
    }

    /**
     * $args[0] is for route uri and $args[1] is either request body or query strings
     *
     * @param $method
     * @param $args
     * @return \Illuminate\Support\Collection|mixed|null
     * @throws ShopifyApiException
     * @throws ShopifyApiResourceNotFoundException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function __call($method, $args)
    {
        list($uri, $params) = [ltrim($args[0], "/"), $args[1] ?? []];
        $response = $this->makeRequest($method, $uri, $params, $this->setXShopifyAccessToken());

        return (is_array($response)) ? $this->convertResponseToCollection($response) : $response;
    }

    /**
     * @param $response
     * @return \Illuminate\Support\Collection
     */
    private function convertResponseToCollection($response)
    {
        return collect(json_decode(json_encode($response)));
    }

    /**
     * @param $method
     * @param $uri
     * @param array $params
     * @param array $headers
     * @return mixed|null
     * @throws ShopifyApiException
     * @throws ShopifyApiResourceNotFoundException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    private function makeRequest($method, $uri, array $params = [], array $headers = [])
    {
        $query = in_array($method, ['get', 'delete']) ? "query" : "json";

        $rateLimit = explode("/", $this->getHeader("X-Shopify-Shop-Api-Call-Limit"));

        if ($rateLimit[0] >= 38) sleep(15);

        $response = $this->client->request(strtoupper($method), $this->baseUrl() . $uri, [
            'headers' => array_merge($headers, $this->requestHeaders),
            $query => $params,
            'timeout' => 120.0,
            'connect_timeout' => 120.0,
            'http_errors' => false,
            "verify" => false
        ]);

        $this->parseResponse($response);
        $responseBody = $this->responseBody($response);

        if (isset($responseBody['errors']) || $response->getStatusCode() >= 400) {
            $errors = is_array($responseBody['errors'])
                ? json_encode($responseBody['errors'])
                : $responseBody['errors'];

            if ($response->getStatusCode() == 404) {
                throw new ShopifyApiResourceNotFoundException(
                    $errors ?? $response->getReasonPhrase(),
                    $response->getStatusCode()
                );
            }

            throw new ShopifyApiException(
                $errors ?? $response->getReasonPhrase(),
                $response->getStatusCode()
            );
        }

        return (is_array($responseBody) && (count($responseBody) > 0)) ? array_shift($responseBody) : $responseBody;
    }

    private function parseResponse($response)
    {
        $this->parseHeaders($response->getHeaders());
        $this->setStatusCode($response->getStatusCode());
        $this->setReasonPhrase($response->getReasonPhrase());
    }

    /**
     * @param $queryParams
     * @return bool
     */
    public function verifyRequest($queryParams): bool
    {
        if (is_string($queryParams)) {
            $data = [];

            $queryParams = explode('&', $queryParams);
            foreach ($queryParams as $queryParam) {
                list($key, $value) = explode('=', $queryParam);
                $data[$key] = urldecode($value);
            }

            $queryParams = $data;
        }

        $hmac = $queryParams['hmac'] ?? '';

        unset($queryParams['signature'], $queryParams['hmac']);

        ksort($queryParams);

        $params = collect($queryParams)->map(function ($value, $key) {
            $key = strtr($key, ['&' => '%26', '%' => '%25', '=' => '%3D']);
            $value = strtr($value, ['&' => '%26', '%' => '%25']);

            return $key . '=' . $value;
        })->implode("&");

        $calculatedHmac = hash_hmac('sha256', $params, $this->secret);

        return hash_equals($hmac, $calculatedHmac);
    }

    /**
     * @param $data
     * @param $hmacHeader
     * @return bool
     */
    public function verifyWebHook($data, $hmacHeader)
    {
        $calculatedHmac = base64_encode(hash_hmac('sha256', $data, $this->secret, true));

        return ($hmacHeader == $calculatedHmac);
    }

    private function setStatusCode(int $code)
    {
        $this->responseStatusCode = $code;
    }

    public function getStatusCode(): int
    {
        return $this->responseStatusCode;
    }

    private function setReasonPhrase($message)
    {
        $this->reasonPhrase = $message;
    }

    public function getReasonPhrase()
    {
        return $this->reasonPhrase;
    }

    private function parseHeaders($headers)
    {
        foreach ($headers as $name => $values) {
            $this->responseHeaders = array_merge($this->responseHeaders, [$name => implode(', ', $values)]);
        }
    }

    public function getHeaders()
    {
        return $this->responseHeaders;
    }

    public function getHeader($header)
    {
        return $this->hasHeader($header) ? $this->responseHeaders[$header] : '';
    }

    public function hasHeader($header)
    {
        return array_key_exists($header, $this->responseHeaders);
    }

    private function responseBody($response)
    {
        return json_decode($response->getBody(), true);
    }

    /**
     * @param string $url
     * @return string
     */
    public function removeProtocol(string $url): string
    {
        $disallowed = ['http://', 'https://', 'http//', 'ftp://', 'ftps://'];
        foreach ($disallowed as $d) {
            if (str_starts_with($url, $d)) {
                return str_replace($d, '', $url);
            }
        }

        return $url;
    }

}
