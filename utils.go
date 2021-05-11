package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func ToHexString(src []byte) string {
	return hex.EncodeToString(src)
}

func GenSHA256(src []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write(src)
	return hash.Sum(nil)
}

func HmacSHA256(data, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return h.Sum(nil)
}

// 获取 origin string 左右之间的 subStr
func GetSubStrHelper(origin, left, right string) string {
	idxLeft := strings.Index(origin, left)
	idxRight := strings.Index(origin, right)

	if idxLeft == -1 || idxRight == -1 {
		return ""
	}

	return origin[(idxLeft + len(left)):idxRight]
}
