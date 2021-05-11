package main

import (
	"unicode"
)

type HeadersList []string

func (h HeadersList) Len() int {
	return len(h)
}

/*
as java CASE_INSENSITIVE_ORDER
忽略大小写的字符串排序
*/
func (h HeadersList) Less(i, j int) bool {
	str1, str2 := h[i], h[j]
	n1, n2 := len(str1), len(str2)
	min := n1
	if n1 > n2 {
		min = n2
	}
	for i := 0; i < min; i++ {
		ch1, ch2 := str1[i], str2[i]
		if ch1 == ch2 {
			continue
		}
		ch1 = byte(unicode.ToUpper(rune(ch1)))
		ch2 = byte(unicode.ToUpper(rune(ch2)))
		if ch1 == ch2 {
			continue
		}
		ch1 = byte(unicode.ToLower(rune(ch1)))
		ch2 = byte(unicode.ToLower(rune(ch2)))
		if ch1 == ch2 {
			continue
		}
		return ch1 < ch2
	}
	return n1 < n2
}

func (h HeadersList) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}
