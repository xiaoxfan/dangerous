package dangerous

import (
	"encoding/json"
)

type JsonAPI interface {
	Load(data []byte) (interface{}, error)
	Dump(v interface{}) (string, error)
}

type Json struct {
}

func (js Json) Load(data []byte) (interface{}, error) {
	var result interface{}
	err := json.Unmarshal(data, &result)
	return result, err
}

func (js Json) Dump(v interface{}) (string, error) {
	str, err := json.Marshal(v)
	return string(str), err
}
