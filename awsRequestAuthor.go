package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	ErrAuthRequestFailed = errors.New("auth request failed")

	ErrAuthRequestHeadAuthorizationMiss     = errors.New("auth param Authorization miss")
	ErrAuthRequestHeadXAmzDateMiss          = errors.New("auth param X-Amz-Date miss")
	ErrAuthRequestHeadXAmzContentSha256Miss = errors.New("auth param X-Amz-Content-Sha256 miss")

	ErrAuthRequestHeadBodyHashIncorrect = errors.New("body hash incorrect")

	ErrAuthRequestUrlXAmzAlgorithmMiss     = errors.New("auth param X-Amz-Algorithm miss")
	ErrAuthRequestUrlXAmzCredentialMiss    = errors.New("auth param X-Amz-Credential miss")
	ErrAuthRequestUrlXAmzDateMiss          = errors.New("auth param X-Amz-Date miss")
	ErrAuthRequestUrlXAmzExpiresMiss       = errors.New("auth param X-Amz-Expires miss")
	ErrAuthRequestUrlXAmzSignedHeadersMiss = errors.New("auth param X-Amz-SignedHeaders miss")
	ErrAuthRequestUrlXAmzSignatureMiss     = errors.New("auth param X-Amz-Signature miss")
)

const (
	S3SignerV4HeadAuthorization = "Authorization"
	S3SignerV4HeadDate          = "X-Amz-Date"
	S3SignerV4HeadBodyHash      = "X-Amz-Content-Sha256"

	S3SignerV4ParseSignedHeadersLeft  = "SignedHeaders="
	S3SignerV4ParseSignedHeadersRight = ", Signature="

	S3SignerV4RegionAndServiceLeft  = "Credential="
	S3SignerV4RegionAndServiceRight = "/aws4_request,"

	S3SignerV4UrlAlgorithm     = "X-Amz-Algorithm"
	S3SignerV4UrlCredential    = "X-Amz-Credential"
	S3SignerV4UrlDate          = "X-Amz-Date"
	S3SignerV4UrlExpires       = "X-Amz-Expires"
	S3SignerV4UrlSignedHeaders = "X-Amz-SignedHeaders"
	S3SignerV4UrlSignature     = "X-Amz-Signature"

	S3SignerV4UrlAlgorithmValue = "AWS4-HMAC-SHA256"

	S3SignerV4DateFormat = "20060102T150405Z"

	S3SignerV4HeadTimeout = time.Minute * 5 // 随便设置一个五分钟超时
)

type AwsRequestAuthor struct {
	signV4 *AwsSignerV4
}

func NewAwsRequestAuthor() *AwsRequestAuthor {
	ra := &AwsRequestAuthor{}
	return ra
}

func (ra *AwsRequestAuthor) AuthRequest(r *http.Request, accessKey, secretKey string) error {
	if r.URL.Query().Get(S3SignerV4UrlSignature) != "" { // 如果url上带了鉴权参数，那就认为是url鉴权
		return ra.AuthRequestWithPresign(r, accessKey, secretKey)
	} else {
		return ra.AuthRequestWithHeadersign(r, accessKey, secretKey)
	}
}

// 对预签名形式的请求进行鉴权
func (ra *AwsRequestAuthor) AuthRequestWithPresign(r *http.Request, accessKey, secretKey string) error {

	headers := make(map[string]string)
	querys := make(map[string]string)

	queryParams := r.URL.Query()

	for key, vals := range queryParams {
		if len(vals) <= 0 {
			continue
		}
		querys[key] = vals[0]
	}

	// 取出 X-Amz-Signature
	signature, ok := querys[S3SignerV4UrlSignature]
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "can not find X-Amz-Signature in query\n")
		return ErrAuthRequestUrlXAmzSignatureMiss
	}

	// 取出 X-Amz-SignedHeaders，并将其中用到的headers取出
	signedHeaderss, ok := querys[S3SignerV4UrlSignedHeaders]
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "can not find X-Amz-SignedHeaders in query\n")
		return ErrAuthRequestUrlXAmzSignedHeadersMiss
	}
	signedHeaders := strings.Split(signedHeaderss, ";")

	headers["Host"] = r.Host
	for _, head := range signedHeaders {
		if head == "host" {
			continue
		}
		val := r.Header.Get(head)
		if len(val) <= 0 {
			_, _ = fmt.Fprintf(os.Stderr, "can not find signedHeader [%s] in headers\n", head)
			return ErrAuthRequestUrlXAmzSignedHeadersMiss
		}
		headers[head] = val
	}

	// 取出 X-Amz-Algorithm，这里只支持 AWS4-HMAC-SHA256
	algorithm, ok := querys[S3SignerV4UrlAlgorithm]
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "can not find X-Amz-Algorithm in query\n")
		return ErrAuthRequestUrlXAmzAlgorithmMiss
	}
	if algorithm != S3SignerV4UrlAlgorithmValue {
		errStr := fmt.Sprintf("not support X-Amz-Algorithm [%s]", algorithm)
		_, _ = fmt.Fprintf(os.Stderr, errStr+"\n")
		return errors.New(errStr)
	}

	// 取出 X-Amz-Credential，并将它解析
	credentialStr, ok := querys[S3SignerV4UrlCredential]
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "can not find X-Amz-Credential in query\n")
		return ErrAuthRequestUrlXAmzCredentialMiss
	}
	credentialParams := strings.Split(credentialStr, "/")
	if len(credentialParams) < 5 {
		_, _ = fmt.Fprintf(os.Stderr, "X-Amz-Credential format error\n")
		return ErrAuthRequestFailed
	}
	ak, dateStamp, regionName, serviceName :=
		credentialParams[0], credentialParams[1], credentialParams[2], credentialParams[3]

	if ak != accessKey {
		_, _ = fmt.Fprintf(os.Stderr, "accessKey incorrect\n")
		return ErrAuthRequestFailed
	}
	sk := secretKey

	// 取出 X-Amz-Date，将它解析为 时间，注意需要解析为 0时区
	timeStamp, ok := querys[S3SignerV4UrlDate]
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "can not find X-Amz-Date in query\n")
		return ErrAuthRequestUrlXAmzDateMiss
	}
	timeReq, err := time.Parse(S3SignerV4DateFormat, timeStamp)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parse X-Amz-Date [%s] failed: %s\n", timeStamp, err)
		errStr := fmt.Sprintf("X-Amz-Date %s format invalid", timeStamp)
		return errors.New(errStr)
	}

	// X-Amz-Date 和 X-Amz-Credential中的日期，两个日期必需是完全一致的
	if !strings.HasPrefix(timeStamp, dateStamp) {
		errStr := fmt.Sprintf("X-Amz-Date [%s] and X-Amz-Credential date [%s] are not same", timeStamp, dateStamp)
		_, _ = fmt.Fprintf(os.Stderr, errStr+"\n")
		return errors.New(errStr)
	}

	// 取出 X-Amz-Date，将它解析为 时间，注意需要解析为 0时区
	expiresSecondStr, ok := querys[S3SignerV4UrlExpires]
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "can not find X-Amz-Expires in query\n")
		return ErrAuthRequestUrlXAmzExpiresMiss
	}
	expireSecond, err := strconv.ParseInt(expiresSecondStr, 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parse X-Amz-Expires failed: %s\n", err)
		errStr := fmt.Sprintf("X-Amz-Expires %s format invalid", expiresSecondStr)
		return errors.New(errStr)
	}

	// 检查签名是否过期 X-Amz-Expires
	timeNow := time.Now().In(time.UTC) // 0时区
	if timeNow.After(timeReq.Add(time.Duration(expireSecond) * time.Second)) {
		errStr := fmt.Sprintf("X-Amz-Date %s X-Amz-Expires %s already timeout", timeStamp, expiresSecondStr)
		_, _ = fmt.Fprintf(os.Stderr, errStr+"\n")
		return errors.New(errStr)
	}

	// 这里需要把 query 中已有的签名去掉，然后再去重新计算
	delete(querys, S3SignerV4UrlSignature)

	/*******************************************************/
	// 签名计算
	authorization := ra.signV4.computerSignatureInUrl(r.Method, r.URL.EscapedPath(),
		headers, querys, UnsignedPayload, ak, sk, regionName, serviceName, timeReq, expireSecond)

	idx := strings.LastIndex(authorization, "=")
	signatureLocal := authorization[idx+1:]

	if signature != signatureLocal {
		_, _ = fmt.Fprintf(os.Stderr, "signature not same\n")
		return ErrAuthRequestFailed
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "Auth Success\n")
		return nil
	}
}

// 对headers形式的请求进行鉴权
func (ra *AwsRequestAuthor) AuthRequestWithHeadersign(r *http.Request, accessKey, secretKey string) error {
	headers := make(map[string]string)
	querys := make(map[string]string)

	queryParams := r.URL.Query()

	for key, vals := range queryParams {
		if len(vals) <= 0 {
			continue
		}
		querys[key] = vals[0]
	}

	// 取出签名 Authorization
	authTarget := r.Header.Get(S3SignerV4HeadAuthorization)
	if len(authTarget) <= 0 {
		_, _ = fmt.Fprintf(os.Stderr, "can not find Authorization in headers\n")
		return ErrAuthRequestHeadAuthorizationMiss
	}

	// 从 Authorization 重解析出 scope
	scopeStr := GetSubStrHelper(authTarget, S3SignerV4RegionAndServiceLeft, S3SignerV4RegionAndServiceRight)
	if len(scopeStr) <= 0 {
		_, _ = fmt.Fprintf(os.Stderr, "parse scope from [%s] failed\n", authTarget)
		return ErrAuthRequestFailed
	}
	// 从 scope 中解析出 ak，date 等信息
	scopeStrs := strings.Split(scopeStr, "/")
	if len(scopeStrs) != 4 {
		_, _ = fmt.Fprintf(os.Stderr, "scope [%s] format invalid\n", scopeStr)
		return ErrAuthRequestFailed
	}
	ak, dateStamp, regionName, serviceName := scopeStrs[0], scopeStrs[1], scopeStrs[2], scopeStrs[3]

	// 比对 ak
	if ak != accessKey {
		_, _ = fmt.Fprintf(os.Stderr, "accessKey incorrect\n")
		return ErrAuthRequestFailed
	}
	sk := secretKey

	// 获取并解析请求日期 X-Amz-Date
	timeStamp := r.Header.Get(S3SignerV4HeadDate)
	if len(timeStamp) <= 0 {
		_, _ = fmt.Fprintf(os.Stderr, "can not find X-Amz-Date in header\n")
		return ErrAuthRequestHeadXAmzDateMiss
	}
	timeReq, err := time.Parse(S3SignerV4DateFormat, timeStamp)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "parse X-Amz-Date [%s] failed: %s\n", timeStamp, err)
		errStr := fmt.Sprintf("X-Amz-Date %s format invalid", timeStamp)
		return errors.New(errStr)
	}

	// X-Amz-Date 和 Authorization 中的日期，两个日期必需是完全一致的
	if !strings.HasPrefix(timeStamp, dateStamp) {
		errStr := fmt.Sprintf("X-Amz-Date [%s] and Authorization date [%s] are not same", timeStamp, dateStamp)
		_, _ = fmt.Fprintf(os.Stderr, errStr+"\n")
		return errors.New(errStr)
	}

	// 取出用于签名的所有 SignedHeaders
	useHeadersStr := GetSubStrHelper(authTarget, S3SignerV4ParseSignedHeadersLeft, S3SignerV4ParseSignedHeadersRight)
	if len(useHeadersStr) <= 0 {
		_, _ = fmt.Fprintf(os.Stderr, "parse SignedHeaders from [%s] failed\n", authTarget)
		return ErrAuthRequestFailed
	}
	useHeaders := strings.Split(useHeadersStr, ";")
	for _, useH := range useHeaders {
		if useH == "host" {
			continue
		}
		headers[useH] = r.Header.Get(useH)
	}
	headers["Host"] = r.Host

	// 时间超时判断，这里随意设置的时长
	timeNow := time.Now().In(time.UTC)
	if timeNow.After(timeReq.Add(S3SignerV4HeadTimeout)) {
		_, _ = fmt.Fprintf(os.Stderr, "req timeout, reqTime [%s] nowTime [%s]\n",
			timeReq.Format(S3SignerV4DateFormat), timeNow.Format(S3SignerV4DateFormat))
		return ErrAuthRequestFailed
	}

	// 取出bodyHash X-Amz-Content-Sha256
	bodyHash := r.Header.Get(S3SignerV4HeadBodyHash)
	if len(bodyHash) <= 0 {
		_, _ = fmt.Fprintf(os.Stderr, "can not find X-Amz-Content-Sha256 in header\n")
		return ErrAuthRequestHeadXAmzContentSha256Miss
	}

	// 把request的内容读取出来，计算hash值，如果body过大的情况，需要重新考虑方法
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, err = ioutil.ReadAll(r.Body)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "read request body failed: %s\n", err)
			return ErrAuthRequestFailed
		}
	}
	bodyHashCompute := EmptyBodySHA256
	if len(bodyBytes) > 0 {
		bodyHashCompute = ToHexString(GenSHA256(bodyBytes))
	}
	if bodyHashCompute != bodyHash {
		_, _ = fmt.Fprintf(os.Stderr, "bodyHash incorrect\n")
		return ErrAuthRequestHeadBodyHashIncorrect
	}
	// 把刚刚读出来的body再写回去
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	/*******************************************************/
	// 签名计算
	authorization := ra.signV4.computerSignatureInHeader(r.Method, r.URL.EscapedPath(),
		headers, querys, bodyHash, ak, sk, regionName, serviceName, timeReq)

	if authTarget != authorization {
		_, _ = fmt.Fprintf(os.Stderr, "signature not same\n")
		return ErrAuthRequestFailed
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "Auth Success\n")
		return nil
	}
}
