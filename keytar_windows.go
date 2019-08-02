package keytar


import (
	"fmt"

	"github.com/danieljoos/wincred"
)

// Utility function to format service/account into something Windows can store
// AND query.  Credentials actually have a username field, but you can't query
// on it, so it wouldn't allow us to store multiple credentials for the same
// service.
func targetFormat(service, account string) string {
	return fmt.Sprintf("%s@%s", account, service)
}

// keychainWindows implements the Keychain interface on Windows by using the
// Credential Vault infrastructure to store items.
type keychainWindows struct{}

func (*keychainWindows) AddPassword(service, account, password string) error {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	passwordValid := isValidNonNullUTF8(password)
	if !(serviceValid && accountValid && passwordValid) {
		return ErrInvalidValue
	}

	cred := wincred.NewGenericCredential(targetFormat(service, account))
	cred.CredentialBlob = []byte(password)
	err := cred.Write()

	return err
}

func (*keychainWindows) GetPassword(service, account string) (string, error) {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	if !(serviceValid && accountValid) {
		return "", ErrInvalidValue
	}

	cred, err := wincred.GetGenericCredential(targetFormat(service, account))

	if err != nil {
		return "", err
	}

	return string(cred.CredentialBlob), nil
}

func (*keychainWindows) DeletePassword(service, account string) error {
	// Validate input
	serviceValid := isValidNonNullUTF8(service)
	accountValid := isValidNonNullUTF8(account)
	if !(serviceValid && accountValid) {
		return ErrInvalidValue
	}

	cred, err := wincred.GetGenericCredential(targetFormat(service, account))
	if err != nil {
		return err
	}
	cred.Delete()

	return nil
}

func init() {
	// Register the OS X keychain implementation
	keychain = &keychainWindows{}
}
