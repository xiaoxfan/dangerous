package dangerous

import (
	"bytes"
	"testing"
)

var (
	valid_bytes = []struct {
		in  string
		out []byte
	}{
		{"test", []byte{116, 101, 115, 116}},
		{"测试", []byte{230, 181, 139, 232, 175, 149}},
		{"測試", []byte{230, 184, 172, 232, 169, 166}},
		{"テスト", []byte{227, 131, 134, 227, 130, 185, 227, 131, 136}},
		{"тестовое задание", []byte{
			209, 130, 208, 181, 209, 129, 209, 130, 208, 190,
			208, 178, 208, 190, 208, 181, 32, 208, 183, 208,
			176, 208, 180, 208, 176, 208, 189, 208, 184, 208,
			181}},
		{"Prüfung", []byte{80, 114, 195, 188, 102, 117, 110, 103}},
		{"테스트", []byte{237, 133, 140, 236, 138, 164, 237, 138, 184}},
	}

	valid_b64 = []struct {
		in    []byte
		out   []byte
		state bool
	}{
		{[]byte(`abcd`), []byte(`YWJjZA`), true},
		{[]byte(`abcd!@#$%^:"`), []byte(`YWJjZCFAIyQlXjoi`), true},
		{[]byte(`1234`), []byte(`MTIzNA`), true},
		{[]byte(`1234!@#$%&&&`), []byte(`MTIzNCFAIyQlJiYm`), true},
		{[]byte(`{}:><>?`), []byte(`e306Pjw-Pw`), true},

		{[]byte(`abcd`), []byte(`YWJjZA==`), false},
		{[]byte(`1234`), []byte(`MTIzNA==`), false},
		{[]byte(`{}:><>?`), []byte(`e306Pjw+Pw==`), true},
	}

	valid_intbyte = []struct {
		_int  int64
		_byte []byte
		state bool
	}{
		{0, []byte{0}, true},
		{4102444800, []byte{244, 134, 87, 0}, true},                                 // 01/01/2100 @ 12:00am (UTC)
		{35659353600, []byte{8, 77, 118, 142, 0}, true},                             // 01/01/3100 @ 12:00am (UTC)
		{9223372036854775807, []byte{127, 255, 255, 255, 255, 255, 255, 255}, true}, // max int64
	}
)

func TestString2Bytes(t *testing.T) {
	for _, valid := range valid_bytes {
		if !bytes.Equal(valid.out, WantBytes(valid.in)) {
			t.Fatalf("Convert string to bytes failded, Input:('%s')", valid.in)
		}
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Recovered in panic:%s, this occurred in function `WantBytes`", r)
		}
	}()
}

func TestB64(t *testing.T) {
	for _, valid := range valid_b64 {
		if result, err := B64decode(valid.out); err == nil {
			if bytes.Equal(result, valid.in) != valid.state {
				t.Fatalf("Base64 decode failed, Input:%s", string(valid.out))
			}

		} else if err != nil && bytes.Contains(valid.out, []byte("=")) {
			continue

		} else {
			t.Fatalf("Base64 decode failed, Input:%s. Error:%s", string(valid.out), err)
		}
	}
}

func TestI2B(t *testing.T) {
	for _, valid := range valid_intbyte {
		if result := Int2Bytes(valid._int); bytes.Equal(result, valid._byte) != valid.state {
			t.Fatalf("Convert Int to Bytes failed, Input:%d.", valid._int)
		}
	}
}

func TestB2I(t *testing.T) {
	for _, valid := range valid_intbyte {
		if result := Bytes2Int(valid._byte); (result == valid._int) != valid.state {
			t.Fatalf("Convert Bytes to Int failed, Input:%v, Output:%d, Excepted:%d.", valid._byte, result, valid._int)
		}
	}

}
