// +build !windows,!darwin,!linux

package keytar

// Keychain factory
// TODO: Does Go's crypto library have something built-in that we can use as a
// fallback?
func NewKeychain() (Keychain, error) {
	return nil, ErrUnsupported
}
