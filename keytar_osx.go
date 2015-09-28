// +build darwin

package keytar

// #cgo LDFLAGS: -framework CoreFoundation -framework Security
// #include <stdlib.h>
// #include <Security/Security.h>
import "C"

import (
	// System imports
	"unsafe"
)

// OS X keychain implementation
type KeychainOSX struct{}

func (KeychainOSX) AddPassword(service, account, password string) error {
	// Convert strings
	serviceLength := C.UInt32(len(service))
	serviceCString := C.CString(service)
	accountLength := C.UInt32(len(account))
	accountCString := C.CString(account)
	passwordLength := C.UInt32(len(password))
	passwordCString := unsafe.Pointer(C.CString(password))

	// Try to add the password
	status := C.SecKeychainAddGenericPassword(
		nil,
		serviceLength,
		serviceCString,
		accountLength,
		accountCString,
		passwordLength,
		passwordCString,
		nil)

	// We're responsible for freeing any C strings generated
	C.free(unsafe.Pointer(serviceCString))
	C.free(unsafe.Pointer(accountCString))
	C.free(passwordCString)

	// Check for errors
	if status != C.errSecSuccess {
		return ErrUnknown
	}

	// All done
	return nil
}

func (KeychainOSX) GetPassword(service, account string) (string, error) {
	// Convert strings
	serviceLength := C.UInt32(len(service))
	serviceCString := C.CString(service)
	accountLength := C.UInt32(len(account))
	accountCString := C.CString(account)

	// Look for a match
	var passwordData unsafe.Pointer
	var passwordDataLength C.UInt32
	status := C.SecKeychainFindGenericPassword(
		nil,
		serviceLength,
		serviceCString,
		accountLength,
		accountCString,
		&passwordDataLength,
		&passwordData,
		nil)

	// We're responsible for freeing the strings
	C.free(unsafe.Pointer(serviceCString))
	C.free(unsafe.Pointer(accountCString))

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
	// Convert strings
	serviceLength := C.UInt32(len(service))
	serviceCString := C.CString(service)
	accountLength := C.UInt32(len(account))
	accountCString := C.CString(account)

	// Grab the item
	var item C.SecKeychainItemRef
	status := C.SecKeychainFindGenericPassword(
		nil,
		serviceLength,
		serviceCString,
		accountLength,
		accountCString,
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
func NewKeychain() Keychain {
	return &KeychainOSX{}
}
