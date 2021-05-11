package main

import (
	"net/http"
	"time"
)

const HttpTimeoutLimit = 5 * time.Second

const UrlStr = "http://example.com/bucket1/test.txt?aa=123&Ab"

const AccessKey = "A7GqwejrKHkJ7K8Tz88u"

const SecretKey = "teFxGLlckz8d1AzzhSTxBhXPIQ7Qq06yAm77SM3M"

const RegionName = "ep-east-1"

const ServiceName = "s3"

const PreSignExpireTime = 60 * 60 * 24

func main() {
	// 测试请求发送
	//sendRequestAuthInHeader(http.MethodPut, UrlStr, []byte("hello world"), AccessKey, SecretKey, RegionName, ServiceName)
	//sendRequestAuthInHeader(http.MethodGet, UrlStr, nil, AccessKey, SecretKey, RegionName, ServiceName)
	//sendRequestAuthInUrl(http.MethodPut, UrlStr, []byte("wakaka"), AccessKey, SecretKey, RegionName, ServiceName, PreSignExpireTime)
	sendRequestAuthInUrl(http.MethodGet, UrlStr, []byte("hello world"), AccessKey, SecretKey, RegionName, ServiceName, PreSignExpireTime)

	// 测试鉴权服务
	//authServer := NewAuthServer()
	//authServer.httpServerRun()
}
