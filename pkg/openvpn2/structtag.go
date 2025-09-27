package openvpn2

import (
	"fmt"
	"reflect"
	"strings"
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

func errorNoReceiverDefined(ty reflect.Type, methodName string) error {
	return fmt.Errorf("no receiver defined on type %v for method %s", ty.String(), methodName)
}

func marshelElem(v interface{}) (*string, error) {
	ty := reflect.TypeOf(v)

	switch ty.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.String:
		s := fmt.Sprintf("%v", v)
		return &s, nil
	case reflect.Bool:
		return nil, nil
	default:
		return nil, errorUnSupportedType(ty)
	}
}

func marshalListlike(v interface{}) (string, error) {

	valAny := reflect.ValueOf(v)

	lst := make([]string, 0)

	for i := 0; i < valAny.Len(); i++ {
		if valAny.Index(i).Kind() == reflect.Pointer && valAny.Index(i).IsNil() {
			continue
		}

		sublst, err := Marshal(valAny.Index(i).Interface())
		if err != nil {
			return "", errorWhileCallingMethod(err, "Marshal")
		}
		lst = append(lst, sublst...)
	}

	return strings.Join(lst, ","), nil
}

const tagName string = "openvpn2"
const tagValEmpty = ""
const tagValSkip = "-"
const interfaceMethodName = "ToCLIArgs"

func marshalStruct(v interface{}) ([]string, error) {
	ty := reflect.TypeOf(v)
	valAny := reflect.ValueOf(v)

	// There might be receiver defined on T or *T
	// such as func (t T) ReceiverFoo() or func (t *T) ReceiverFoo()
	// also have to deal with such case.

	// Try func (t T) ToCLIArgs()
	method := valAny.MethodByName(interfaceMethodName)
	if !method.IsZero() {
		callRetVals := method.Call(nil)
		return callRetVals[0].Interface().([]string), callRetVals[1].Interface().(error)
	}

	// Try func (t *T) ToCLIArgs()
	if valAny.CanAddr() {
		method := valAny.Addr().MethodByName(interfaceMethodName)
		if !method.IsZero() {
			callRetVals := method.Call(nil)
			return callRetVals[0].Interface().([]string), callRetVals[1].Interface().(error)
		}
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
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.String, reflect.Bool:
		sPtr, err := marshelElem(v)
		if err != nil {
			return nil, errorWhileCallingMethod(err, "marshelElem")
		}
		if sPtr != nil && *sPtr != "" {
			return []string{*sPtr}, nil
		}
	case reflect.Slice, reflect.Array:
		v, err := marshalListlike(v)
		if err != nil {
			return nil, errorWhileCallingMethod(err, "marshalListlike")
		}

		return []string{v}, nil
	case reflect.Pointer:
		if !reflect.ValueOf(v).IsNil() {
			return Marshal(reflect.ValueOf(v).Elem().Interface())
		}
	case reflect.Struct:
		return marshalStruct(v)
	case reflect.Interface:
		if !reflect.ValueOf(v).IsNil() {
			method := reflect.ValueOf(v).MethodByName(interfaceMethodName)
			if method.IsZero() {
				return nil, errorNoReceiverDefined(ty, interfaceMethodName)
			}
			callRetVals := method.Call(nil)
			return callRetVals[0].Interface().([]string), callRetVals[1].Interface().(error)
		}
	default:
		return nil, errorUnSupportedType(ty)
	}

	return res, nil
}
