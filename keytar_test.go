package keytar

import "testing"

// Testing constants
const (
	NonExistentService = "keytar-test-bad-service"
	NonExistentAccount = "keytar-test-bad-account"
	Service            = "keytar-test-service-世界.example.org"
	Account            = "keytar-世界"
	Password           = "$uP3RSecre7世界"
	AlternatePassword  = "GeorgeWashington"
)

// Test that a non-existent lookup fails
func TestNonExistentGet(t *testing.T) {
	// Create a keychain
	keychain, err := NewKeychain()
	if err != nil {
		t.Fatalf("unable to create keychain")
	}

	// Test that a non-existent lookup fail
	password, err := keychain.GetPassword(
		NonExistentService,
		NonExistentAccount)
	if password != "" || err == nil {
		t.Error("retrieval of non-existent service/account password succeeded " + password)
	}
}

func TestNonExistentReplace(t *testing.T) {
	// Create a keychain
	keychain, err := NewKeychain()
	if err != nil {
		t.Fatalf("unable to create keychain")
	}

	// Replace the password
	err = ReplacePassword(
		keychain,
		NonExistentService,
		NonExistentAccount,
		AlternatePassword)
	if err != nil {
		t.Error("replacement of non-existent password failed")
	}

	// Get/verify the alternate password
	password, err := keychain.GetPassword(
		NonExistentService,
		NonExistentAccount)
	if err != nil {
		t.Error("password retrieval failed")
	}
	if password != AlternatePassword {
		t.Error("password mismatch")
	}

	// Delete it
	err = keychain.DeletePassword(NonExistentService, NonExistentAccount)
	if err != nil {
		t.Error("password deletion failed")
	}
}

// Make sure the standard password lifecycle works
func TestLifecycle(t *testing.T) {
	// Create a keychain
	keychain, err := NewKeychain()
	if err != nil {
		t.Fatalf("unable to create keychain")
	}

	// Add a password
	err = keychain.AddPassword(Service, Account, Password)
	if err != nil {
		t.Error("password addition failed")
	}

	// Get/verify the password
	password, err := keychain.GetPassword(Service, Account)
	if err != nil {
		t.Error("password retrieval failed")
	}
	if password != Password {
		t.Error("password mismatch")
	}

	// Replace the password
	err = ReplacePassword(keychain, Service, Account, AlternatePassword)
	if err != nil {
		t.Error("password replacement failed")
	}

	// Get/verify the alternate password
	password, err = keychain.GetPassword(Service, Account)
	if err != nil {
		t.Error("password retrieval failed")
	}
	if password != AlternatePassword {
		t.Error("password mismatch")
	}

	// Delete the password
	err = keychain.DeletePassword(Service, Account)
	if err != nil {
		t.Error("password deletion failed")
	}
}
