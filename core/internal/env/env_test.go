package env

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	file := filepath.Join(t.TempDir(), ".env")
	content := "# commento\n" +
		"HW_T_A=uno\n" +
		"export HW_T_B = \"due tre\"\n" +
		"HW_T_C='quattro'\n" +
		"HW_T_D=dal-file\n" +
		"riga senza uguale\n" +
		"HW_T_E=a=b\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HW_T_D", "ambiente")
	for _, k := range []string{"HW_T_A", "HW_T_B", "HW_T_C", "HW_T_E"} {
		t.Setenv(k, "") // registra il ripristino a fine test
		os.Unsetenv(k)
	}
	if err := Load(file); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"HW_T_A": "uno", "HW_T_B": "due tre", "HW_T_C": "quattro", "HW_T_D": "ambiente", "HW_T_E": "a=b"}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q, atteso %q", k, got, v)
		}
	}
	if err := Load(filepath.Join(t.TempDir(), "manca")); err != nil {
		t.Fatalf("un file mancante non è un errore: %v", err)
	}
}

func TestTypedGetters(t *testing.T) {
	t.Setenv("HW_T_INT", " 42 ")
	t.Setenv("HW_T_BAD", "x")
	t.Setenv("HW_T_BOOL", "true")
	t.Setenv("HW_T_DUR", "90s")
	t.Setenv("HW_T_FLOAT", "2.5")
	t.Setenv("HW_T_STR", "  ")
	if Int("HW_T_INT", 1) != 42 || Int("HW_T_BAD", 7) != 7 {
		t.Error("Int")
	}
	if !Bool("HW_T_BOOL", false) || Bool("HW_T_BAD", false) {
		t.Error("Bool")
	}
	if Duration("HW_T_DUR", 0) != 90*time.Second || Duration("HW_T_BAD", time.Minute) != time.Minute {
		t.Error("Duration")
	}
	if Float("HW_T_FLOAT", 0) != 2.5 {
		t.Error("Float")
	}
	if Str("HW_T_STR", "predefinito") != "predefinito" {
		t.Error("Str: solo spazi vale come vuoto")
	}
}
