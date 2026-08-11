package config

import (
	"reflect"
	"testing"
)

func TestNativeMTCPolicyLinterDefaults(t *testing.T) {
	if Config.Linter.Mtclint.NumGoroutines != 1 {
		t.Errorf("mtclint numGoroutines = %d, want 1", Config.Linter.Mtclint.NumGoroutines)
	}
	if Config.Linter.Cqrplint.NumGoroutines != 1 {
		t.Errorf("cqrplint numGoroutines = %d, want 1", Config.Linter.Cqrplint.NumGoroutines)
	}
}

func TestNativeMTCPolicyLinterMapstructureNames(t *testing.T) {
	linterType, ok := reflect.TypeOf(Config).FieldByName("Linter")
	if !ok {
		t.Fatal("Config.Linter field is missing")
	}
	tests := []struct {
		field string
		tag   string
	}{
		{"Mtclint", "mtclint"},
		{"Cqrplint", "cqrplint"},
	}
	for _, tc := range tests {
		field, ok := linterType.Type.FieldByName(tc.field)
		if !ok {
			t.Errorf("Config.Linter.%s field is missing", tc.field)
			continue
		}
		if got := field.Tag.Get("mapstructure"); got != tc.tag {
			t.Errorf("Config.Linter.%s mapstructure tag = %q, want %q", tc.field, got, tc.tag)
		}
		numGoroutines, ok := field.Type.FieldByName("NumGoroutines")
		if !ok || numGoroutines.Tag.Get("mapstructure") != "numGoroutines" {
			t.Errorf("Config.Linter.%s.NumGoroutines mapstructure tag is missing", tc.field)
		}
	}
}
