package dangerous

import ()

type TimedSerializer struct {
	Serializer
}

func (self TimedSerializer) Loads(s string, max_age int64) (interface{}, error) {
	(&self).Serializer.SetDefault()
	for _, signer := range self.IterUnSigners() {
		base64d, err := signer.(SignerAPI).UnSignTimestamp(s, max_age)
		if err != nil {
			return nil, err
		}
		payload, err := self.LoadPayload(base64d)
		return payload, err
	}
	return nil, nil
}
