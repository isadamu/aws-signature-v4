package main

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	EmptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	UnsignedPayload = "UNSIGNED-PAYLOAD"

	Scheme     = "AWS4"
	Algorithm  = "HMAC-SHA256"
	Terminator = "aws4_request"

	SignerV4TimeFormat = "20060102T150405Z"
	SignerV4DateFormat = "20060102"
)

type AwsSignerV4 struct {
}

func NewSignerV4() *AwsSignerV4 {
	sign := &AwsSignerV4{}

	return sign
}

/*
返回请求需要加上的头部，包含签名与相关参数
*/
func (sign *AwsSignerV4) SignRequestInHeader(method, urlStr string, body []byte,
	ak, sk, regionName, serviceName string) (map[string]string, error) {

	headers := make(map[string]string)
	querys := make(map[string]string)

	u, err := sign.helpParseUrl(urlStr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parse url [%s] failed: %s\n", urlStr, err)
		return headers, err
	}

	host := u.Host

	headers["Host"] = host

	bodyHash := EmptyBodySHA256
	if len(body) > 0 {
		bodyHash = ToHexString(GenSHA256(body))

		// 如果body不是空，才需要在计算时加入 content-length
		headers["content-length"] = strconv.Itoa(len(body))
	}

	headers["x-amz-content-sha256"] = bodyHash

	// 认为query里面不会由重复的字段
	// 否则鉴权一定会失败
	for key, vals := range u.Query() {
		if len(vals) <= 0 {
			continue
		}
		querys[key] = vals[0]
	}

	authorization := sign.computerSignatureInHeader(method, u.EscapedPath(),
		headers, querys, bodyHash, ak, sk, regionName, serviceName, time.Now().In(time.UTC))

	headers["Authorization"] = authorization

	return headers, nil
}

/*
返回加上了预签名的url
*/
func (sign *AwsSignerV4) SignRequestInUrl(method, urlStr string,
	ak, sk, regionName, serviceName string, expireSecond int64) (string, error) {

	u, err := sign.helpParseUrl(urlStr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parse url [%s] failed: %s\n", urlStr, err)
		return "", err
	}

	headers := make(map[string]string)
	querys := make(map[string]string)

	headers["Host"] = u.Host

	// 认为query里面不会由重复的字段
	// 否则鉴权一定会失败
	for key, vals := range u.Query() {
		if len(vals) <= 0 {
			continue
		}
		querys[key] = vals[0]
	}

	authorization := sign.computerSignatureInUrl(method, u.EscapedPath(),
		headers, querys, UnsignedPayload, ak, sk, regionName, serviceName, time.Now().In(time.UTC), expireSecond)

	presignedUrl := urlStr
	if len(u.RawQuery) > 0 {
		presignedUrl += "&" + authorization
	} else {
		presignedUrl += "?" + authorization
	}

	return presignedUrl, nil
}

func (sign *AwsSignerV4) computerSignatureInHeader(method, path string, headers, queryParams map[string]string,
	bodyHash string, ak, sk, regionName, serviceName string, dateTime time.Time) string {

	// 需要使用UTC时区，也就是0时区
	timeStamp := dateTime.Format(SignerV4TimeFormat)
	dateStamp := dateTime.Format(SignerV4DateFormat)

	headers["x-amz-date"] = timeStamp
	scope := dateStamp + "/" + regionName + "/" + serviceName + "/" + Terminator

	canonicalizeHeaderNames, canonicalizeHeadersPairs := sign.genCanonicalizeHeaderNamesAndPairs(headers)

	canonicalizeQueryPairs := sign.genCanonicalizeQueryPairs(queryParams)

	signature := sign.genSignature(timeStamp, dateStamp,
		method, path, regionName, serviceName, scope,
		canonicalizeQueryPairs, canonicalizeHeaderNames, canonicalizeHeadersPairs,
		bodyHash,
		sk)

	credentialHeader := "Credential=" + ak + "/" + scope
	signedHeaderNames := "SignedHeaders=" + canonicalizeHeaderNames
	signatureHeader := "Signature=" + signature

	authorizationHeader := Scheme + "-" + Algorithm + " " +
		credentialHeader + ", " +
		signedHeaderNames + ", " +
		signatureHeader

	return authorizationHeader
}

func (sign *AwsSignerV4) computerSignatureInUrl(method, path string, headers, queryParams map[string]string,
	bodyHash string, ak, sk, regionName, serviceName string, dateTime time.Time, expireSecond int64) string {

	canonicalizeHeaderNames, canonicalizeHeadersPairs := sign.genCanonicalizeHeaderNamesAndPairs(headers)

	// 需要使用UTC时区，也就是0时区
	//timeNow, _ := time.Parse(SignerV4TimeFormat, "20210416T062311Z")
	timeStamp := dateTime.Format(SignerV4TimeFormat)
	dateStamp := dateTime.Format(SignerV4DateFormat)

	scope := dateStamp + "/" + regionName + "/" + serviceName + "/" + Terminator

	queryParams["X-Amz-Expires"] = strconv.FormatInt(expireSecond, 10)
	queryParams["X-Amz-Algorithm"] = Scheme + "-" + Algorithm
	queryParams["X-Amz-Credential"] = ak + "/" + scope
	queryParams["X-Amz-Date"] = timeStamp
	queryParams["X-Amz-SignedHeaders"] = canonicalizeHeaderNames

	canonicalizeQueryPairs := sign.genCanonicalizeQueryPairs(queryParams)

	signature := sign.genSignature(timeStamp, dateStamp,
		method, path, regionName, serviceName, scope,
		canonicalizeQueryPairs, canonicalizeHeaderNames, canonicalizeHeadersPairs,
		bodyHash,
		sk)

	buf := new(bytes.Buffer)
	buf.WriteString("X-Amz-Algorithm=" + queryParams["X-Amz-Algorithm"])
	buf.WriteString("&X-Amz-Credential=" + queryParams["X-Amz-Credential"])
	buf.WriteString("&X-Amz-Date=" + queryParams["X-Amz-Date"])
	buf.WriteString("&X-Amz-Expires=" + queryParams["X-Amz-Expires"])
	buf.WriteString("&X-Amz-SignedHeaders=" + queryParams["X-Amz-SignedHeaders"])
	buf.WriteString("&X-Amz-Signature=" + signature)

	return buf.String()
}

/*
返回
签名用的 headers 的key组成的字符串 names，例如:
			content-length;host;x-amz-content-sha256;x-amz-date

签名用的 headers 的key value组成的字符串 Pairs，例如：
			content-length:6
			host:aaa.com:8060
			x-amz-content-sha256:bf12345a2ab188b9a6f0580dc66d9f47e928fd404a0933a0ecce5e9ed46b893b
			x-amz-date:20200116T021535Z
*/
func (sign *AwsSignerV4) genCanonicalizeHeaderNamesAndPairs(headers map[string]string) (string, string) {
	var keys []string
	for key := range headers {
		keys = append(keys, key)
	}

	sort.Sort(HeadersList(keys))

	namesBuf := new(bytes.Buffer)
	pairsBuf := new(bytes.Buffer)

	re, _ := regexp.Compile("\\s+") //把匹配的所有空白字符替换成空格
	for i, key := range keys {
		namesBuf.WriteString(strings.ToLower(key))
		if i < len(keys)-1 {
			namesBuf.WriteByte(';')
		}

		val := headers[key]

		pairsBuf.WriteString(re.ReplaceAllString(strings.ToLower(key), " "))
		pairsBuf.WriteByte(':')
		pairsBuf.WriteString(re.ReplaceAllString(strings.TrimSpace(val), " "))
		pairsBuf.WriteByte('\n')
	}

	return namesBuf.String(), pairsBuf.String()
}

/*
返回 query 组成的字符串，例如：
	X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=xxx%2F20200315%2Fep-east-1%2Fs3%2Faws4_request&X-Amz-Date=20200315T062311Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
*/
func (sign *AwsSignerV4) genCanonicalizeQueryPairs(params map[string]string) string {
	if params == nil || len(params) <= 0 {
		return ""
	}

	var keys []string
	for key := range params {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	buf := new(bytes.Buffer)
	for i, key := range keys {
		val := params[key]
		buf.WriteString(url.PathEscape(key))
		buf.WriteString("=")
		buf.WriteString(url.PathEscape(val))
		if i < len(keys)-1 {
			buf.WriteByte('&')
		}
	}

	return buf.String()
}

func (sign *AwsSignerV4) genCanonicalRequest(httpMethod, path, queryParameters,
	canonicalizeHeaderNames, canonicalizeHeaders, bodyHash string) string {

	canonicalRequest := httpMethod + "\n" +
		path + "\n" +
		queryParameters + "\n" +
		canonicalizeHeaders + "\n" +
		canonicalizeHeaderNames + "\n" +
		bodyHash

	return canonicalRequest
}

func (sign *AwsSignerV4) genStringToSign(scheme, algorithm, timeStamp,
	scope, canonicalRequest string) string {

	stringToSign := scheme + "-" + algorithm + "\n" +
		timeStamp + "\n" +
		scope + "\n" +
		ToHexString(GenSHA256([]byte(canonicalRequest)))

	return stringToSign
}

/*
根据参数计算出签名。
无论header还是url签名最后都是同一算法，只是它们参数获取的方式不太一样
*/
func (sign *AwsSignerV4) genSignature(timeStamp, dateStamp,
	method, path, regionName, serviceName, scope,
	canonicalizeQueryPairs, canonicalizeHeaderNames, canonicalizeHeadersPairs,
	bodyHash,
	sk string) string {

	canonicalRequest := sign.genCanonicalRequest(method, path,
		canonicalizeQueryPairs, canonicalizeHeaderNames,
		canonicalizeHeadersPairs, bodyHash)

	fmt.Println("--------- Canonical request --------")
	fmt.Println(canonicalRequest)
	fmt.Println("------------------------------------")

	stringToSign := sign.genStringToSign(Scheme, Algorithm, timeStamp, scope, canonicalRequest)

	fmt.Println("--------- String to sign -----------")
	fmt.Println(stringToSign)
	fmt.Println("------------------------------------")

	kSecret := []byte(Scheme + sk)
	kDate := HmacSHA256([]byte(dateStamp), kSecret)
	kRegion := HmacSHA256([]byte(regionName), kDate)
	kService := HmacSHA256([]byte(serviceName), kRegion)
	kSigning := HmacSHA256([]byte(Terminator), kService)
	signature := HmacSHA256([]byte(stringToSign), kSigning)

	return ToHexString(signature)
}

func (sign *AwsSignerV4) helpParseUrl(urlStr string) (*url.URL, error) {
	// 注意这里存在一个问题
	// 如果 url 形如 http://xxx.com:1111
	// u.EscapedPath() 会得到 "" ，这会导致签名错误而出现403
	// 所以这里需要对 url 进行检查，如果 u.EscapedPath() 是 "" ，则补上一个 "/"，变为 http://xxx.com:1111/
	var u *url.URL
	var err error
	u, err = url.Parse(urlStr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parse url [%s] failed: %s\n", urlStr, err)
		return nil, err
	}
	if u.EscapedPath() == "" {
		urlStr += "/"
		u, err = url.Parse(urlStr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "parse url [%s] failed: %s\n", urlStr, err)
			return nil, err
		}
	}
	return u, nil
}
