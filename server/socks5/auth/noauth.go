package auth

import "io"

type noAuth struct{}

func NoAuth() *noAuth {
	return &noAuth{}
}

func (a *noAuth) Code() byte {
	return NoAuthMethodRequiredCode
}

func (a *noAuth) String() string {
	return "NO AUTHENTICATION REQUIRED"
}

func (a *noAuth) Handle(rw io.ReadWriter) error {
	return nil
}
