package keytar

import (
	// System imports
	"unsafe"
)

// Returns a raw pointer to the bytes underlying a string.  Only use this
// function if you can accept the underlying encoding, can manually specify the
// length of the string (since it won't be null-terminated), and only need the
// result temporarily (since it might be garbage collected after you release a
// reference to the string).
func rawStringPtr(s string) unsafe.Pointer {
	return unsafe.Pointer(&((([]byte)(s))[0]))
}
