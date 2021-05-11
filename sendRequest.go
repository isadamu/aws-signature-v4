package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
)

func sendRequestAuthInHeader(method, urlStr string, content []byte, ak, sk, regionName, serviceName string) {

	sign := NewSignerV4()

	headers, err := sign.SignRequestInHeader(method, urlStr, content, ak, sk, regionName, serviceName)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sign request failed: %s\n", err)
		return
	}

	var req *http.Request
	if len(content) > 0 {
		req, err = http.NewRequest(method, urlStr, bytes.NewReader(content))
	} else {
		req, err = http.NewRequest(method, urlStr, nil)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "new request for [%s] failed: %s\n", urlStr, err)
		return
	}

	for key, val := range headers {
		if key == "content-length" { // 这个不需要写在header里面，请求自己会带上
			continue
		}
		req.Header[key] = []string{val}
	}

	fmt.Println("--------- Request headers --------")
	for key, val := range req.Header {
		fmt.Println(key, ":", val)
	}
	fmt.Println("------------------------------------")

	client := http.Client{
		Timeout: HttpTimeoutLimit,
	}
	res, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "send req failed: %s\n", err)
		return
	}

	_, _ = fmt.Fprintf(os.Stdout, "response status: %d\n", res.StatusCode)
	_, _ = fmt.Fprintf(os.Stdout, "response headers: \n%+v\n", res.Header)
}

func sendRequestAuthInUrl(method, urlStr string, content []byte, ak, sk, regionName, serviceName string, expireSecond int64) {

	sign := NewSignerV4()

	urlWithSign, err := sign.SignRequestInUrl(method, urlStr, ak, sk, regionName, serviceName, expireSecond)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sign request failed: %s\n", err)
		return
	}

	fmt.Println("--------- urlWithSign --------")
	fmt.Println(urlWithSign)
	fmt.Println("------------------------------------")

	var req *http.Request
	if len(content) > 0 {
		req, err = http.NewRequest(method, urlWithSign, bytes.NewReader(content))
	} else {
		req, err = http.NewRequest(method, urlWithSign, nil)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "new request for [%s] failed: %s\n", urlStr, err)
		return
	}

	client := http.Client{
		Timeout: HttpTimeoutLimit,
	}
	res, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "send req failed: %s\n", err)
		return
	}

	_, _ = fmt.Fprintf(os.Stdout, "response status: %d\n", res.StatusCode)
	_, _ = fmt.Fprintf(os.Stdout, "response headers: \n%+v\n", res.Header)
}
