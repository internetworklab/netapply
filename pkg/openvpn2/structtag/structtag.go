package structtag

import (
	"fmt"
	"reflect"
)

// This package implements the `openvpn2` struct tag.

// For example, given the following struct:
//
// ```go
// type OpenVPN2 struct {
// 	Server string `openvpn2:"server"`
// 	Port   int    `openvpn2:"port"`
// 	Proto  string `openvpn2:"proto"`
// 	User   string `openvpn2:"user"`
// 	Password string `openvpn2:"password"`
// }
// ```
// We can marshal it to the following CLI arguments:
// ["--server", "server", "--port", "port", "--proto", "proto", "--user", "user", "--password", "password"]
//

func errorUnSupportedType(ty reflect.Type) error {
	return fmt.Errorf("unsupported Type %s of kind %s", ty.String(), ty.Kind())
}

func errorWhileCallingMethod(err error, methodName string) error {
	return fmt.Errorf("failed to call method %s: %v", methodName, err)
}

const tagName string = "openvpn2"
const tagValEmpty = ""
const tagValSkip = "-"
const interfaceMethodName = "ToCLIArgs"

func callCustomMethod(method reflect.Value) ([]string, error) {
	var firstRetVal []string
	var secondRetVal error
	callRetVals := method.Call(nil)

	if len(callRetVals) > 0 {
		if !callRetVals[0].IsNil() {
			firstRetVal = callRetVals[0].Interface().([]string)
		}
		if len(callRetVals) > 1 {
			if !callRetVals[1].IsNil() {
				secondRetVal = callRetVals[1].Interface().(error)
			}
		}
	}

	return firstRetVal, secondRetVal
}

func marshalStructOrPointerToStruct(v interface{}) ([]string, error) {
	ty := reflect.TypeOf(v)
	valAny := reflect.ValueOf(v)

	// There might be receiver defined on T or *T
	// such as func (t T) ReceiverFoo() or func (t *T) ReceiverFoo()
	// also have to deal with such case.

	// Try func (t *T) ToCLIArgs()
	if valAny.Kind() == reflect.Pointer {
		if method := valAny.MethodByName(interfaceMethodName); method.IsValid() {
			return callCustomMethod(method)
		}

		return Marshal(valAny.Elem().Interface())
	}

	// Try func (t T) ToCLIArgs()
	if method := valAny.MethodByName(interfaceMethodName); method.IsValid() {
		return callCustomMethod(method)
	}

	res := make([]string, 0)

	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		tagval := field.Tag.Get(tagName)
		if tagval == tagValEmpty || tagval == tagValSkip {
			continue
		}

		fieldVal := valAny.Field(i)
		if fieldVal.Type().Kind() == reflect.Pointer {
			if fieldVal.IsNil() {
				continue
			}

			if fieldVal.Elem().Kind() == reflect.Bool {
				boolVal := fieldVal.Elem().Interface().(bool)
				if !boolVal {
					continue
				}
			}
		}

		if fieldVal.Kind() == reflect.Bool {
			boolVal := fieldVal.Interface().(bool)
			if !boolVal {
				continue
			}
		}

		res = append(res, fmt.Sprintf("--%s", tagval))

		subCLIArgs, err := Marshal(fieldVal.Interface())
		if err != nil {
			return nil, errorWhileCallingMethod(err, "Marshal")
		}
		res = append(res, subCLIArgs...)
	}

	return res, nil
}

func Marshal(v interface{}) ([]string, error) {
	ty := reflect.TypeOf(v)
	res := make([]string, 0)

	switch ty.Kind() {
	case reflect.Bool:
		return res, nil
	case reflect.String:
		s := reflect.ValueOf(v).String()
		if s != "" {
			return []string{s}, nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return []string{fmt.Sprintf("%v", v)}, nil
	case reflect.Slice, reflect.Array:
		for i := 0; i < reflect.ValueOf(v).Len(); i++ {
			if reflect.ValueOf(v).Index(i).Kind() == reflect.Pointer && reflect.ValueOf(v).Index(i).IsNil() {
				// skip nil pointer elem on a listlike object
				continue
			}

			sublst, err := Marshal(reflect.ValueOf(v).Index(i).Interface())
			if err != nil {
				return nil, errorWhileCallingMethod(err, "Marshal")
			}
			res = append(res, sublst...)
		}

		return res, nil
	case reflect.Pointer:
		if reflect.ValueOf(v).IsNil() {
			return nil, nil
		}

		if reflect.ValueOf(v).Elem().Kind() == reflect.Struct {
			return marshalStructOrPointerToStruct(v)
		}

		return Marshal(reflect.ValueOf(v).Elem().Interface())
	case reflect.Struct:
		return marshalStructOrPointerToStruct(v)
	case reflect.Interface:
		if !reflect.ValueOf(v).IsNil() {
			method := reflect.ValueOf(v).MethodByName(interfaceMethodName)
			if !method.IsZero() {
				callRetVals := method.Call(nil)
				return callRetVals[0].Interface().([]string), callRetVals[1].Interface().(error)
			}

			return Marshal(reflect.ValueOf(v).Elem().Interface())
		}
	default:
		return nil, errorUnSupportedType(ty)
	}

	return res, nil
}
