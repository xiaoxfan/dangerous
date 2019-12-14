package dangerous

import (
	"bytes"
)

func ByteCompare(a, b []byte) bool {
	return bytes.Compare(a, b) == 0
}

func StrCompare(a, b string) bool {
	return ByteCompare([]byte(a), []byte(b))
}
