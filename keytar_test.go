package keytar

import "testing"

// Testing constants
const (
	NonExistentService = "keytar-test-bad-service"
	NonExistentAccount = "keytar-test-bad-account"
	Service            = "keytar-test-service-世界"
	Account            = "keytar-世界@example.org"
	Password           = "$uP3RSecre7世界"
	AlternatePassword  = "GeorgeWashington"
)

// Create a keychain
var keychain = NewKeychain()

// Test that a non-existent lookup fails
func TestNonExistentGet(t *testing.T) {
	p, e := keychain.GetPassword(NonExistentService, NonExistentAccount)
	if p != "" || e == nil {
		t.Error("retrieval of non-existent service/account password succeeded")
	}
}

// Make sure replace password works for non-existent passwords
func TestNonExistentReplace(t *testing.T) {
	// Replace the password
	e := ReplacePassword(
		keychain,
		NonExistentService,
		NonExistentAccount,
		AlternatePassword)
	if e != nil {
		t.Error("replacement of non-existent password failed")
	}

	// Get/verify the alternate password
	p, e := keychain.GetPassword(NonExistentService, NonExistentAccount)
	if e != nil {
		t.Error("password retrieval failed")
	}
	if p != AlternatePassword {
		t.Error("password mismatch")
	}

	// Delete it
	e = keychain.DeletePassword(NonExistentService, NonExistentAccount)
	if e != nil {
		t.Error("password deletion failed")
	}
}

// Make sure the standard password lifecycle works
func TestLifecycle(t *testing.T) {
	// Add a password
	e := keychain.AddPassword(Service, Account, Password)
	if e != nil {
		t.Error("password addition failed")
	}

	// Get/verify the password
	p, e := keychain.GetPassword(Service, Account)
	if e != nil {
		t.Error("password retrieval failed")
	}
	if p != Password {
		t.Error("password mismatch")
	}

	// Replace the password
	e = ReplacePassword(keychain, Service, Account, AlternatePassword)
	if e != nil {
		t.Error("password replacement failed")
	}

	// Get/verify the alternate password
	p, e = keychain.GetPassword(Service, Account)
	if e != nil {
		t.Error("password retrieval failed")
	}
	if p != AlternatePassword {
		t.Error("password mismatch")
	}

	// Delete the password
	e = keychain.DeletePassword(Service, Account)
	if e != nil {
		t.Error("password deletion failed")
	}
}
