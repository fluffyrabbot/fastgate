package main

import (
	"encoding/base64"
	"fastgate/decision-service/internal/token"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOperatorListenerRequiresLoopback(t *testing.T) {
	for _, addr := range []string{"", "127.0.0.1:9091", "[::1]:9091"} {
		if err := validateOperatorListen(addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{":9091", "0.0.0.0:9091", "192.0.2.1:9091", "localhost:9091", "garbage"} {
		if err := validateOperatorListen(addr); err == nil {
			t.Errorf("accepted %s", addr)
		}
	}
}

func TestVisitorClearanceCannotReadOperatorData(t *testing.T) {
	kr, err := token.NewKeyring("HS256", map[string]string{"test": base64.RawURLEncoding.EncodeToString([]byte("disposable-test-key-for-operator-boundary"))}, "test", "test", 0)
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := kr.Sign("high", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := kr.Verify(visitor, 0); err != nil || !valid {
		t.Fatal("fixture token invalid")
	}
	mux := http.NewServeMux()
	denyPublicOperatorEndpoints(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	for _, path := range []string{"/metrics", "/admin/stats"} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: "Clearance", Value: visitor})
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != 404 {
			t.Fatalf("public %s: %d", path, res.Code)
		}
		res = httptest.NewRecorder()
		operatorHandler().ServeHTTP(res, req)
		if res.Code != 200 {
			t.Fatalf("operator %s: %d", path, res.Code)
		}
	}
}
