package dangerous

import (
	"encoding/json"
)

// JSONAPI used to solve the problem that applying new struct to `serializer` or `jws`
type JSONAPI interface {
	Load(data []byte) (interface{}, error)
	Dump(v interface{}) (string, error)
}

// JSON is a empty struct, just for applying
type JSON struct {
}

// Load is totally equal to json.Unmarshal
func (js JSON) Load(data []byte) (interface{}, error) {
	var result interface{}
	err := json.Unmarshal(data, &result)
	return result, err
}

// Dump is equal to json.Marshal
func (js JSON) Dump(v interface{}) (string, error) {
	str, err := json.Marshal(v)
	return string(str), err
}
