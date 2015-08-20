<?php

/**
 * Created by openssl.
 * Author: "626895154@qq.com"
 * Date: 2015/8/19
 * Time: 14:21
 */
class Openssl
{
    private $_priKey;
    private $_pubKey;
    private $_keyPath;

    public function __construct($path)
    {
        if(empty($path) || !is_dir($path)){
            throw new Exception('Must set the keys save path');
        }
        $this->_keyPath = $path;
    }

    public function createKey()
    {
        $r = openssl_pkey_new();
        openssl_pkey_export($r, $priKey);
        file_put_contents($this->_keyPath . DIRECTORY_SEPARATOR . 'pri.key', $priKey);
        $this->_priKey = openssl_pkey_get_private($priKey);

        $rp = openssl_pkey_get_details($r);
        $pubKey = $rp['key'];
        file_put_contents($this->_keyPath . DIRECTORY_SEPARATOR .  'pub.key', $pubKey);
        $this->_pubKey = openssl_pkey_get_public($pubKey);
    }

    public function setupPriKey()
    {
        if(is_resource($this->_priKey)){
            return true;
        }
        $file = $this->_keyPath . DIRECTORY_SEPARATOR . 'pri.key';
        $prk = file_get_contents($file);
        $this->_priKey = openssl_pkey_get_private($prk);
        return true;
    }

    public function setupPubKey()
    {
        if(is_resource($this->_pubKey)){
            return true;
        }
        $file = $this->_keyPath . DIRECTORY_SEPARATOR .  'pub.key';
        $puk = file_get_contents($file);
        $this->_pubKey = openssl_pkey_get_public($puk);
        return true;
    }

    public function priEncrypt($data)
    {
        if(!is_string($data)){
            return null;
        }
        $this->setupPriKey();
        $r = openssl_private_encrypt($data, $encrypted, $this->_priKey);
        if($r){
            return base64_encode($encrypted);
        }
        return null;
    }

    public function priDecrypt($encrypted)
    {
        if(!is_string($encrypted)){
            return null;
        }
        $this->setupPriKey();
        $encrypted = base64_decode($encrypted);
        $r = openssl_private_decrypt($encrypted, $decrypted, $this->_priKey);
        if($r){
            return $decrypted;
        }
        return null;
    }

    public function pubEncrypt($data)
    {
        if(!is_string($data)){
            return null;
        }
        $this->setupPubKey();
        $r = openssl_public_encrypt($data, $encrypted, $this->_pubKey);
        if($r){
            return base64_encode($encrypted);
        }
        return null;
    }

    public function pubDecrypt($cryptData)
    {
        if(!is_string($cryptData)){
            return null;
        }
        $this->setupPubKey();
        $cryptData = base64_decode($cryptData);
        $r = openssl_public_decrypt($cryptData, $decrypted, $this->_pubKey);
        if($r){
            return $decrypted;
        }
        return null;
    }

    /**
     * 数据签名
     * @param $data
     * @return null|string
     */
    public function signData($data)
    {
        if(!is_string($data)){
            return null;
        }
        $this->setupPriKey();
        $res=openssl_sign($data,$signature,$this->_priKey,OPENSSL_ALGO_SHA256);
        if(!$res){
            return null;
        }
        return base64_encode($signature);
    }

    /**
     * 验签
     * @param $data
     * @param $signature
     * @return bool|null|string
     */
    public function verifySign($data,$signature)
    {
        $this->setupPubKey();
        $signature = base64_decode($signature);
        $res=openssl_verify($data,$signature,$this->_pubKey,"sha256WithRSAEncryption");
        if($res===1){
            return true;
        }elseif($res===0){
            return false;
        }else{
            return openssl_error_string();
        }
    }
    public function __destruct()
    {
        @ fclose($this->_priKey);
        @ fclose($this->_pubKey);
    }
}