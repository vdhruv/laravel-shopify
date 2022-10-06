<?php

namespace Vdhruv\Shopify\Exceptions;

use Exception;

class ShopifyApiResourceNotFoundException extends Exception
{
    /**
     * ShopifyApiException constructor.
     * @param $message
     * @param int $code code
     */
    public function __construct($message, int $code)
    {
        parent::__construct($message, $code);
    }
}