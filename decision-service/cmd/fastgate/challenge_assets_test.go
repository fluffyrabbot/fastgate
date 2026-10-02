package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestChallengeAssetsStartupValidation(t *testing.T) {
	directory := t.TempDir()
	if _, err := newChallengeAssets(filepath.Join(directory, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory must fail startup: %v", err)
	}
	file := filepath.Join(directory, "file")
	if err := os.WriteFile(file, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newChallengeAssets(file); err == nil {
		t.Fatal("regular file must fail startup")
	}
	// Retain existing startup contract: contents can be populated separately.
	if _, err := newChallengeAssets(directory); err != nil {
		t.Fatal(err)
	}
}

func TestChallengeAssetsServingContract(t *testing.T) {
	directory := t.TempDir()
	for name, body := range map[string]string{"index.html": "<h1>Challenge fixture</h1>", "app.js": "window.challengeFixture = true;"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	assets, err := newChallengeAssets(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"/__uam", "/custom-challenge"} {
		t.Run(prefix, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle(prefix+"/", http.StripPrefix(prefix, assets))
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "origin fixture", http.StatusForbidden) })
			for _, tt := range []struct {
				path   string
				status int
				body   string
			}{
				{prefix + "/", 200, "<h1>Challenge fixture</h1>"},
				{prefix + "/app.js", 200, "window.challengeFixture = true;"},
				{prefix + "/missing.js", 404, ""},
				{"/protected", 403, "origin fixture\n"},
			} {
				res := httptest.NewRecorder()
				mux.ServeHTTP(res, httptest.NewRequest("GET", tt.path, nil))
				if res.Code != tt.status {
					t.Fatalf("%s: status %d, want %d", tt.path, res.Code, tt.status)
				}
				if tt.body != "" && res.Body.String() != tt.body {
					t.Fatalf("%s: unexpected body %q", tt.path, res.Body.String())
				}
			}
			redirect := httptest.NewRecorder()
			mux.ServeHTTP(redirect, httptest.NewRequest("GET", prefix, nil))
			// Match the pre-refactor stdlib mount; Go versions differ in redirect status.
			previous := http.NewServeMux()
			previous.Handle(prefix+"/", http.StripPrefix(prefix, http.FileServer(http.Dir(directory))))
			previous.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "origin fixture", http.StatusForbidden) })
			baseline := httptest.NewRecorder()
			previous.ServeHTTP(baseline, httptest.NewRequest("GET", prefix, nil))
			if redirect.Code != baseline.Code || redirect.Header().Get("Location") != baseline.Header().Get("Location") || redirect.Header().Get("Location") != prefix+"/" {
				t.Fatalf("slash redirect changed: %d %q", redirect.Code, redirect.Header().Get("Location"))
			}
		})
	}
}
