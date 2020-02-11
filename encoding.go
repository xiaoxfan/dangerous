package dangerous

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		panic(fmt.Sprintf("Erorr occurred when using WantBytes, error:%s input:%s", err.Error(), str))
	} else if err != nil && strings.Contains(err.Error(), "EOF") {
		return []byte{}
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

func Bytes2Int(_byte []byte) (_int int64) {
	for i := 1; i < 10; i++ {
		if len(_byte)/(i*8) < 1 {
			x00 := make([]byte, i*8-len(_byte))
			_byte, _ = Concentrate(x00, _byte)
			break
		} else if len(_byte) == 8 {
			break
		}
	}
	bytesBuffer := bytes.NewBuffer(_byte)
	binary.Read(bytesBuffer, binary.BigEndian, &_int)
	return
}

func Int2Bytes(_int int64) (bs []byte) {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, _int)
	bs = bytesBuffer.Bytes()
	for p, i := range bs {
		if i != 0 {
			return bs[p:]
		}
	}
	if bytes.Equal(bs, []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		bs = []byte{0}
	}
	return
}

var Base64Alphabet = WantBytes("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=")
