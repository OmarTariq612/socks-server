package auth

import (
	"crypto/subtle"
	"errors"
	"io"
)

const (
	subnegotiationVersion = 1

	successStatus = 0
	failedStatus  = 1
)

var (
	success = [2]byte{subnegotiationVersion, successStatus}
	failed  = [2]byte{subnegotiationVersion, failedStatus}
)

var ErrAuthFailed = errors.New("auth failed: username or password is incorrect")

type usernamePassword struct {
	Username string
	Password string
}

func NewUsernamePassword(username, password string) *usernamePassword {
	return &usernamePassword{
		Username: username,
		Password: password,
	}
}

func (a *usernamePassword) Code() byte {
	return UsernamePasswordCode
}

func (a *usernamePassword) String() string {
	return "USERNAME/PASSWORD"
}

func (a *usernamePassword) Handle(rw io.ReadWriter) error {
	var buf [255]byte
	if _, err := io.ReadFull(rw, buf[:2]); err != nil {
		return err
	}

	usernameLen := int(buf[1])

	if _, err := io.ReadFull(rw, buf[:usernameLen+1]); err != nil {
		return err
	}

	username := string(buf[:usernameLen])
	passwordLen := int(buf[usernameLen])

	if _, err := io.ReadFull(rw, buf[:passwordLen]); err != nil {
		return err
	}

	password := string(buf[:passwordLen])
	usernameCompResult := subtle.ConstantTimeCompare([]byte(username), []byte(a.Username))
	passwordCompResult := subtle.ConstantTimeCompare([]byte(password), []byte(a.Password))

	if usernameCompResult != 1 || passwordCompResult != 1 {
		a.fail(rw)
		return ErrAuthFailed
	}

	a.success(rw)
	return nil
}

func (a *usernamePassword) success(w io.Writer) {
	w.Write(success[:])
}

func (a *usernamePassword) fail(w io.Writer) {
	w.Write(failed[:])
}
