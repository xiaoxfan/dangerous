package dangerous

import (
	"encoding/base64"
	"encoding/binary"
	"golang.org/x/net/html/charset"
	"io/ioutil"
	"strings"
)

func WantBytes(str string, chartype ...interface{}) []byte {
	types := "utf-8"
	if len(types) == 1 {
		types = chartype[0].(string)
	}
	r, err := charset.NewReader(strings.NewReader(str), types)
	if err != nil {
		panic(err)
	}
	result, _ := ioutil.ReadAll(r)
	return []byte(result)
}

func B64encode(msg []byte) string {
	return base64.RawURLEncoding.EncodeToString(msg)
}

func B64decode(encoded []byte) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(string(encoded))
	return decoded, err
}

func Bytes2Int(_byte []byte) int64 {
	for i := 1; i < 10; i++ {
		if len(_byte)/(i*8) < 1 {
			x00 := make([]byte, i*8-len(_byte))
			_byte, _ = Concentrate(x00, _byte)
			break
		}
	}
	return int64(binary.BigEndian.Uint64(_byte))
}

func Int2Bytes(_int int64) []byte {
	bs := make([]byte, 128)
	binary.BigEndian.PutUint64(bs, uint64(_int))
	return []byte(strings.Replace(string(bs), "\x00", "", -1))
}

var Base64_alphabet = WantBytes("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=")
