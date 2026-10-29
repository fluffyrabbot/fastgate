package config

import (
	"strings"
	"testing"
)

const (
	productionTemplate = "../../../config.production.yaml"
	developmentConfig  = "../../../config.yaml"
	freshSecret        = "q2Hk6v9hY3pW1nC8tR5uX0zA7bE4dG2jL6mN9sV3wQ8="
	otherFreshSecret   = "Zm9yZ2V0LW1lLW5vdC10aGlzLWlzLWEtZnJlc2gta2V5"
)

func clearSecretEnv(t *testing.T) {
	t.Helper()
	t.Setenv(TokenSecretEnv, "")
	t.Setenv(ClusterSecretEnv, "")
	t.Setenv("FASTGATE_ALLOW_TEST_KEYS", "")
}

func TestProductionTemplateHoldsNoSecrets(t *testing.T) {
	clearSecretEnv(t)
	cfg, err := Load(productionTemplate)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for kid, key := range cfg.Token.Keys {
		if key != "" {
			t.Errorf("token.keys[%s] is set in the committed template", kid)
		}
	}
	if cfg.Cluster.SecretKey != "" {
		t.Error("cluster.secret_key is set in the committed template")
	}
}

func TestSecretEnvFillsProductionTemplate(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv(TokenSecretEnv, freshSecret)
	t.Setenv(ClusterSecretEnv, otherFreshSecret)
	cfg, err := Load(productionTemplate)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Token.Keys[cfg.Token.CurrentKID]; got != freshSecret {
		t.Errorf("token key = %q, want value of %s", got, TokenSecretEnv)
	}
	if cfg.Cluster.SecretKey != otherFreshSecret {
		t.Errorf("cluster.secret_key = %q, want value of %s", cfg.Cluster.SecretKey, ClusterSecretEnv)
	}
}

func TestValidateRejectsEmptyTokenKey(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv(ClusterSecretEnv, freshSecret)
	cfg, err := Load(productionTemplate)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), TokenSecretEnv) {
		t.Fatalf("Validate() = %v, want an error naming %s", err, TokenSecretEnv)
	}
}

func TestValidateRejectsEmptyClusterSecret(t *testing.T) {
	clearSecretEnv(t)
	t.Setenv(TokenSecretEnv, freshSecret)
	cfg, err := Load(productionTemplate)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), ClusterSecretEnv) {
		t.Fatalf("Validate() = %v, want an error naming %s", err, ClusterSecretEnv)
	}
}

func TestValidateRejectsPublishedKeys(t *testing.T) {
	for key, name := range publishedKeys {
		t.Run(name, func(t *testing.T) {
			clearSecretEnv(t)
			t.Setenv(TokenSecretEnv, key)
			t.Setenv(ClusterSecretEnv, freshSecret)
			cfg, err := Load(developmentConfig)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			err = cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("Validate() = %v, want rejection of %s", err, name)
			}
		})
	}
}
