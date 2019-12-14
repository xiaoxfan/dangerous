package dangerous

import (
	"fmt"
	"reflect"
)

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
