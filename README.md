# itsdangerous-go

[![Build Status](https://travis-ci.com/kcorlidy/dangerous.svg?branch=master)](https://travis-ci.com/kcorlidy/dangerous) [![codecov](https://codecov.io/gh/kcorlidy/dangerous/branch/master/graph/badge.svg)](https://codecov.io/gh/kcorlidy/dangerous) [![Go Report Card](https://goreportcard.com/badge/github.com/kcorlidy/dangerous)](https://goreportcard.com/report/github.com/kcorlidy/dangerous)

`itsdangerous-go` is coded according to [`itsdangerous`](https://github.com/pallets/itsdangerous). Due to golang's inheritance rule and it is  strongly typed language, so `itsdangerous-go` does not have the identical API to origin version. But `itdangerous-go` can do what `itsdangerous` did, for that reason you can try to do something that you did in python.



## Installing

```
go get -u github.com/kcorlidy/itsdangerous-go
```



## A Simple Example

```go
package main

import (
	"fmt"
	"github.com/kcorlidy/dangerous"
)

func main() {
    data := map[string]interface{}{"id": 5, "name": "itsdangerous"}
    // Signer's default digest method is sha256
	ser := dangerous.Serializer{Secret: "secret key", Salt: "auth"}
	result, _ := ser.URLSafeDumps(data)
	fmt.Println(string(result))
	fmt.Println(ser.URLSafeLoads(string(result)))
}
```

### Equal to python code

```python
from itsdangerous import URLSafeSerializer
import hashlib
#  Signer's default digest method is sha1
auth_s = URLSafeSerializer("secret key", "auth",signer_kwargs={"digest_method": hashlib.sha256})
token = auth_s.dumps({"id": 5, "name": "itsdangerous"})

print(token)
# eyJpZCI6NSwibmFtZSI6Iml0c2Rhbmdlcm91cyJ9.sMTJJoYOuSliwOpT81Z_Ql4OIPQacePyoz79f3x_MEo

data = auth_s.loads(token)
print(data["name"])
```
