package dangerous

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"reflect"
)

func ByteCompare(a, b []byte) bool {
	return bytes.Compare(a, b) == 0
}

func ApplyKwargs(struct1 interface{}, kwargs map[string]interface{}) error {
	values1 := reflect.ValueOf(struct1).Elem()
	if values1.Type().Kind() != reflect.Struct {
		return fmt.Errorf("please input struct")
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recover from Panic:", r, ">This error occurs when you set a not exist field.<")
		}
	}()
	for k, v := range kwargs {
		values1.FieldByName(k).Set(reflect.ValueOf(v))
	}
	return nil
}

func RSplit(b, sep []byte) ([]byte, []byte) {
	index := bytes.LastIndex(b, sep)
	if index == -1 {
		return b, []byte("")
	}
	return b[:index], b[index+1:]
}

func Concentrate(b ...interface{}) ([]byte, error) {
	var bytes_ bytes.Buffer

	for _, itf := range b {
		_byte, ok := itf.([]byte)
		if !ok {
			return bytes_.Bytes(), fmt.Errorf("Concentrate bytes only!")
		}
		bytes_.Write(_byte)
	}
	return bytes_.Bytes(), nil
}

func Compress(src []byte) []byte {
	var in bytes.Buffer
	w := zlib.NewWriter(&in)
	w.Write(src)
	w.Close()
	return in.Bytes()
}

func UnCompress(data []byte) ([]byte, error) {
	b := bytes.NewReader(data)
	var out bytes.Buffer
	r, err := zlib.NewReader(b)
	io.Copy(&out, r)
	r.Close()
	return out.Bytes(), err
}
