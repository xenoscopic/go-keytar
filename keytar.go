package keytar

import (
	// System imports
	"errors"
)

// Error definitions
var (
	ErrUnknown  = errors.New("unknown keychain failure")
	ErrNotFound = errors.New("keychain entry not found")
)

// All string passed to this interface must be encoded in UTF-8
type Keychain interface {
	AddPassword(service, account, password string) error
	GetPassword(service, account string) (string, error)
	DeletePassword(service, account string) error
}

// Create a common replace function.  It'd be nice if this common implementation
// could be baked into the Keychain interface, but such is Go...
func ReplacePassword(k Keychain, service, account, newPassword string) error {
	// Delete the password, ignoring not-found errors
	e := k.DeletePassword(service, account)
	if e != nil && e != ErrNotFound {
		return e
	}

	// Add the new password
	return k.AddPassword(service, account, newPassword)
}
