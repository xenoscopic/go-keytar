package keytar

// #cgo LDFLAGS: -framework CoreFoundation -framework Security
// #include <CoreFoundation/CoreFoundation.h>
// #include <Security/Security.h>
import "C"

import (
	// System imports
	"unicode/utf8"
	"unsafe"
)

// OS X keychain implementation
type KeychainOSX struct{}

func (KeychainOSX) AddPassword(service, account, password string) error {
	// Validate input
	serviceValid := utf8.ValidString(service)
	accountValid := utf8.ValidString(account)
	passwordValid := utf8.ValidString(password)
	if !(serviceValid && accountValid && passwordValid) {
		return ErrInvalidValue
	}

	// Try to add the password
	status := C.SecKeychainAddGenericPassword(
		nil,
		C.UInt32(len(service)),
		(*C.char)(rawStringPtr(service)),
		C.UInt32(len(account)),
		(*C.char)(rawStringPtr(account)),
		C.UInt32(len(password)),
		rawStringPtr(password),
		nil)

	// Check for errors
	if status != C.errSecSuccess {
		return ErrUnknown
	}

	// All done
	return nil
}

func (KeychainOSX) GetPassword(service, account string) (string, error) {
	// Validate input
	serviceValid := utf8.ValidString(service)
	accountValid := utf8.ValidString(account)
	if !(serviceValid && accountValid) {
		return "", ErrInvalidValue
	}

	// Look for a match
	var passwordData unsafe.Pointer
	var passwordDataLength C.UInt32
	status := C.SecKeychainFindGenericPassword(
		nil,
		C.UInt32(len(service)),
		(*C.char)(rawStringPtr(service)),
		C.UInt32(len(account)),
		(*C.char)(rawStringPtr(account)),
		&passwordDataLength,
		&passwordData,
		nil)

	// Check for errors
	if status != C.errSecSuccess {
		return "", ErrNotFound
	}

	// Create the result
	result := C.GoStringN((*C.char)(passwordData), C.int(passwordDataLength))

	// Cleanup the temporary buffer
	C.SecKeychainItemFreeContent(nil, passwordData)

	// All done
	return result, nil
}

func (KeychainOSX) DeletePassword(service, account string) error {
	// Validate input
	serviceValid := utf8.ValidString(service)
	accountValid := utf8.ValidString(account)
	if !(serviceValid && accountValid) {
		return ErrInvalidValue
	}

	// Grab the item
	var item C.SecKeychainItemRef
	status := C.SecKeychainFindGenericPassword(
		nil,
		C.UInt32(len(service)),
		(*C.char)(rawStringPtr(service)),
		C.UInt32(len(account)),
		(*C.char)(rawStringPtr(account)),
		nil,
		nil,
		&item)

	// Check for errors
	if status != C.errSecSuccess {
		return ErrNotFound
	}

	// Delete the item
	status = C.SecKeychainItemDelete(item)

	// Free the item
	C.CFRelease(C.CFTypeRef(item))

	// Check for errors
	if status != C.errSecSuccess {
		return ErrUnknown
	}

	// All done
	return nil
}

// Keychain factory
func NewKeychain() (Keychain, error) {
	return &KeychainOSX{}, nil
}
