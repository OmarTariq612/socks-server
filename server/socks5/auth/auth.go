package auth

import (
	"fmt"
	"io"
)

// o  X'00' NO AUTHENTICATION REQUIRED
// o  X'01' GSSAPICode
// o  X'02' USERNAME/PASSWORD
// o  X'03' to X'7F' IANA ASSIGNED
// o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
// o  X'FF' NO ACCEPTABLE METHODS
const (
	NoAuthMethodRequiredCode byte = 0x00
	GSSAPICode               byte = 0x01
	UsernamePasswordCode     byte = 0x02
	NoAcceptableMethodCode   byte = 0xFF
)

type AuthMethod interface {
	Code() byte
	String() string
	Handle(rw io.ReadWriter) error
}

func ValidateAuthMethods(methods []AuthMethod) error {
	for _, method := range methods {
		code := method.Code()
		if !((NoAuthMethodRequiredCode <= code && code <= UsernamePasswordCode) || (0x80 <= code && code <= 0xFE)) {
			return fmt.Errorf("invalid auth code (%d) with name (%s)", code, method.String())
		}
	}
	return nil
}
