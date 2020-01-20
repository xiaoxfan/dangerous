package dangerous

/*
type URLSafeTimedSerializer struct {
	TimedSerializer
}

func (self URLSafeTimedSerializer) LoadPayload(payload []byte) (interface{}, error) {
	data, err := self.URLSafeSerializerMixin.LoadPayload(payload)
	if err != nil {
		return data, err
	}
	return self.TimedSerializer.LoadPayload(data)
}

func (self URLSafeTimedSerializer) DumpPayload(obj interface{}) ([]byte, error) {
	str, err := self.TimedSerializer.DumpPayload(obj)
	_byte := WantBytes(str)
	if err != nil {
		return _byte, err
	}
	return self.URLSafeSerializerMixin.DumpPayload(_byte)
}
*/
