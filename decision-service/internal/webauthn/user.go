package webauthn

import (
	"crypto/rand"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User implements the webauthn.User interface for ephemeral (anonymous) users.
// FastGate doesn't maintain user accounts, so each challenge creates a temporary user.
type User struct {
	ID          []byte
	Name        string
	DisplayName string
}

// WebAuthnID returns the user's ID (required by webauthn.User interface)
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the user's name (required by webauthn.User interface)
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name (required by webauthn.User interface)
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon returns the user's icon URL (required by webauthn.User interface)
func (u *User) WebAuthnIcon() string {
	return "" // No icon for anonymous users
}

// WebAuthnCredentials returns the user's credentials (required by webauthn.User interface)
// For FastGate's use case, we don't store credentials (stateless authentication)
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return nil // Stateless - no stored credentials
}

// NewEphemeralUser creates a new ephemeral user with a random ID.
// This user exists only for the duration of the challenge flow.
func NewEphemeralUser() (*User, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}

	return &User{
		ID:          id,
		Name:        "anonymous",
		DisplayName: "Anonymous User",
	}, nil
}
