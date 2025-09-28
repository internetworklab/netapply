package daemons

import (
	"context"
	"fmt"
	"reflect"
	"strings"
)

const tagNameYAML = "yaml"
const tagNameJSON = "json"

const tagValEmpty = ""
const tagValSkip = "-"

func getTag(st reflect.StructField) string {
	tryTagNames := []string{tagNameYAML, tagNameJSON}
	for _, tagName := range tryTagNames {
		if v := st.Tag.Get(tagName); v != "" {
			segs := strings.Split(v, ",")
			if len(segs) > 0 {
				for _, seg := range segs {
					segtrim := strings.TrimSpace(seg)
					if segtrim != "" {
						return segtrim
					}
				}
			}
		}
	}
	return ""
}

func getBoolRepresentation(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func marshalFRRDaemonsConfig(v interface{}) ([]string, error) {
	ty := reflect.TypeOf(v)
	if ty.Kind() == reflect.Pointer {
		if v == nil {
			return nil, fmt.Errorf("frr daemons config is nil")
		}

		return marshalFRRDaemonsConfig(reflect.ValueOf(v).Elem().Interface())
	}

	if ty.Kind() != reflect.Struct {
		return nil, fmt.Errorf("frr daemons config is not a struct")
	}

	result := make([]string, 0)

	valAny := reflect.ValueOf(v)
	for i := 0; i < ty.NumField(); i++ {
		tag := getTag(ty.Field(i))
		if tag == tagValEmpty || tag == tagValSkip {
			continue
		}

		fieldVal := valAny.Field(i)

		if fieldVal.Kind() == reflect.Pointer {
			if fieldVal.IsNil() {
				continue
			}
			fieldVal = fieldVal.Elem()
		}

		if fieldVal.Kind() == reflect.Bool {
			result = append(result, fmt.Sprintf("%s=%s", tag, getBoolRepresentation(fieldVal.Interface().(bool))))
			continue
		}

		if fieldVal.Kind() == reflect.Slice || fieldVal.Kind() == reflect.Array {
			segs := make([]string, 0)
			segs = append(segs, " ")
			for j := 0; j < fieldVal.Len(); j++ {
				segs = append(segs, fieldVal.Index(j).String())
			}
			result = append(result, fmt.Sprintf("%s=%s", tag, "\""+strings.Join(segs, " ")+"\""))
			continue
		}

		return nil, fmt.Errorf("unsupported field type: %s %s", fieldVal.Type().String(), fieldVal.Kind())
	}

	return result, nil
}

func (enabledDaemonsConfig *FRREnabledDaemonsConfig) ToConfigLines(ctx context.Context) ([]string, error) {
	return marshalFRRDaemonsConfig(enabledDaemonsConfig)
}

func (perDaemonCLIArgumentsConfig *FRRPerDaemonCLIArgumentsConfig) ToConfigLines(ctx context.Context) ([]string, error) {
	return marshalFRRDaemonsConfig(perDaemonCLIArgumentsConfig)
}

func (daemonsConfig *FRRDaemonsConfig) ToConfigLines(ctx context.Context) ([]string, error) {
	daemonsEnabledConfigLines, err := daemonsConfig.EnableDaemons.ToConfigLines(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to convert enable daemons config to config lines: %w", err)
	}

	perDaemonCLIArgumentsConfigLines, err := daemonsConfig.PerDaemonCLIArguments.ToConfigLines(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to convert per daemon cli arguments config to config lines: %w", err)
	}

	result := make([]string, 0)
	result = append(result, daemonsEnabledConfigLines...)
	result = append(result, perDaemonCLIArgumentsConfigLines...)

	return result, nil
}

func DefaultFRREnabledDaemonsConfig() *FRREnabledDaemonsConfig {
	cfg := new(FRREnabledDaemonsConfig)
	cfg.EnableBGPd = true
	cfg.EnableOSPFd = true
	cfg.EnableOSPF6d = true
	return cfg
}

func DefaultFRRPerDaemonCLIArgumentsConfig() *FRRPerDaemonCLIArgumentsConfig {
	cfg := new(FRRPerDaemonCLIArgumentsConfig)
	cfg.VtyshEnabled = true
	cfg.ZebraOptions = []string{"-A", "127.0.0.1", "-s", "90000000"}
	cfg.MGMTdOptions = []string{"-A", "127.0.0.1"}
	cfg.BGPdOptions = []string{"-A", "127.0.0.1", "-M", "rpki"}
	cfg.OSPFdOptions = []string{"-A", "127.0.0.1"}
	cfg.OSPF6dOptions = []string{"-A", "::1"}
	cfg.RIPdOptions = []string{"-A", "127.0.0.1"}
	cfg.RIPNGdOptions = []string{"-A", "::1"}
	cfg.ISISdOptions = []string{"-A", "127.0.0.1"}
	cfg.PIMdOptions = []string{"-A", "127.0.0.1"}
	cfg.PIM6dOptions = []string{"-A", "::1"}
	cfg.LDPdOptions = []string{"-A", "127.0.0.1"}
	cfg.NHRPdOptions = []string{"-A", "127.0.0.1"}
	cfg.EIGRPdOptions = []string{"-A", "127.0.0.1"}
	cfg.BabeldOptions = []string{"-A", "127.0.0.1"}
	cfg.SharpdOptions = []string{"-A", "127.0.0.1"}
	cfg.PBRdOptions = []string{"-A", "127.0.0.1"}
	cfg.StaticdOptions = []string{"-A", "127.0.0.1"}
	cfg.BFDDdOptions = []string{"-A", "127.0.0.1"}
	cfg.FabricdOptions = []string{"-A", "127.0.0.1"}
	cfg.VRRPdOptions = []string{"-A", "127.0.0.1"}
	cfg.PathdOptions = []string{"-A", "127.0.0.1"}

	return cfg
}

func DefaultFRRDaemonsConfig() *FRRDaemonsConfig {
	cfg := new(FRRDaemonsConfig)
	cfg.EnableDaemons = *DefaultFRREnabledDaemonsConfig()
	cfg.PerDaemonCLIArguments = *DefaultFRRPerDaemonCLIArgumentsConfig()
	return cfg
}
