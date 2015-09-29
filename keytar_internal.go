package keytar

import (
	// System imports
	"unsafe"
	"unicode/utf8"
)

// Returns a raw pointer to the bytes underlying a string.  Only use this
// function if you can accept the underlying encoding, can manually specify the
// length of the string (since it won't be null-terminated), and only need the
// result temporarily (since it might be garbage collected after you release a
// reference to the string).
func rawStringPtr(s string) unsafe.Pointer {
	return unsafe.Pointer(&((([]byte)(s))[0]))
}

// Validates a string as UTF-8 with no null bytes
func isValidNonNullUTF8(s string) bool {
	// Check that this is valid UTF-8
	if !utf8.ValidString(s) {
		return false
	}

	// Check that there are no null-bytes (which are allowed by UTF-8)
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return false
		}
	}

	// All done
	return true
}
