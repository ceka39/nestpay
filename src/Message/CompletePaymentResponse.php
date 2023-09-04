<?php

namespace Omnipay\Nestpay\Message;

use Omnipay\Common\Message\AbstractResponse;
use Omnipay\Common\Message\RequestInterface;
use Omnipay\Common\Exception\InvalidResponseException;

/**
 * @property CompletePaymentRequest $request
 */
class CompletePaymentResponse extends AbstractResponse
{

    public function __construct(RequestInterface $request, $data)
    {
        $this->request = $request;
        $this->data = $data;
        if (!$this->signHash()) {
            throw new InvalidResponseException('Sayısal İmza Doğrulanmadı');
        }
    }

    public function isSuccessful()
    {
        return in_array($this->data['mdStatus'], [1, 2, 3, 4]) && $this->data["Response"] === 'Approved';
    }

    public function getMessage()
    {
        return isset($this->data['ErrMsg']) ? $this->data['ErrMsg'] : $this->data['mdErrorMsg'];
    }

    public function getTransactionId()
    {
        return $this->data['TransId'];
    }

    public function getTransactionReference()
    {
        return $this->data['HostRefNum'];
    }

    public function getAmount()
    {
        return $this->data['amount'];
    }

    public function getCurrency()
    {
        return $this->data['currency'];
    }

    public function getOrderId()
    {
        return $this->data['ReturnOid'];
    }

    private function signHash()
    {
        if ($this->data["hashAlgorithm"] == "ver3") {
            $dataKeys = array_keys($this->data);
            natcasesort($dataKeys);
            $dataKeys = array_values($dataKeys);
            $signature = [];
            foreach ($dataKeys as $key) {
                $escapedValue = str_replace("|", "\\|", str_replace("\\", "\\\\", $this->data[$key]));

                $lowerKey = strtolower($key);
                if ($lowerKey != "hash" && $lowerKey != "encoding") {
                    $signature[$key] = $escapedValue;
                }
            }
            $signature["storekey"] = str_replace("|", "\\|", str_replace("\\", "\\\\", $this->request->getStoreKey()));
            $generateHash = base64_encode(pack(
                'H*',
                hash('sha512', implode("|", $signature))
            ));
            if ($generateHash != $this->data["HASH"]) {
                return false;
            }
            return true;
        } else {
            $hashParams = explode(':', $this->data['HASHPARAMS']);
            $signature = "";
            foreach ($hashParams as $parameter) {
                if (isset($this->data[$parameter])) {
                    $signature .= $this->data[$parameter];
                }
            }
            $generateHash = base64_encode(pack('H*', sha1($signature . $this->request->getStoreKey())));
            if ($signature != $this->data["HASHPARAMSVAL"] || $generateHash != $this->data["HASH"]) {
                return false;
            }
            return true;
        }
    }
}
