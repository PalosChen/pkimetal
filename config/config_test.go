package config

import (
	"os"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

func TestApplicationConfigurationIsLoadedAndMalformedInputFails(t *testing.T) {
	original := Config
	t.Cleanup(func() { Config = original; viper.Reset() })
	t.Chdir(t.TempDir())
	if err := os.WriteFile("application.yml", []byte("server:\n  webserverPort: 19876\n"), 0600); err != nil {
		t.Fatal(err)
	}
	viper.Reset()
	if err := initViper(); err != nil {
		t.Fatal(err)
	}
	if Config.Server.WebserverPort != 19876 {
		t.Fatalf("application.yml ignored: port = %d", Config.Server.WebserverPort)
	}
	if err := os.WriteFile("application.yml", []byte("server: [unterminated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	viper.Reset()
	if err := initViper(); err == nil {
		t.Fatal("malformed application.yml must fail instead of using defaults")
	}
}

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
