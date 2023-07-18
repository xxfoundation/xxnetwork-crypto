////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package tls

import (
	"errors"
	"os"
	"testing"

	"github.com/mitchellh/go-homedir"
	"google.golang.org/grpc/credentials"

	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/crypto/testkeys"
	"gitlab.com/xx_network/primitives/utils"
)

// Happy path.
func TestGetFullPath(t *testing.T) {
	h, _ := homedir.Dir()
	p := "~/test/test"
	full := getFullPath(p)
	if full != h+p[1:] {
		t.Errorf("Failed")
	}
}

// Happy path.
func TestNewCredentialsFromFile(t *testing.T) {
	path := testkeys.GetTestCertPath()
	tlsCreds, err := NewCredentialsFromFile(path, "")
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if tlsCreds == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

// Error path: Tests that NewCredentialsFromFile returns os.ErrNotExist for a
// file that does not exist.
func TestNewCredentialsFromFileError_BadPath(t *testing.T) {
	path := testkeys.GetTestCertPath() + "abc"
	_, err := NewCredentialsFromFile(path, "")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Did not receive expected error for an invalid path."+
			"\nexpected: %v\nreceived: %+v", os.ErrNotExist, err)
	}
}

// Error path: Tests that NewCredentialsFromFile returns an error for an invalid
// cert file
func TestNewCredentialsFromFileError_BadKey(t *testing.T) {
	path := testkeys.GetTestKeyPath()
	_, err := NewCredentialsFromFile(path, "")
	if err == nil {
		t.Errorf("Failed to receive error for invalid cert file.")
	}
}

// Happy path of NewCredentialsFromPEM.
func TestNewCredentialsFromPEM(t *testing.T) {
	var tlsCreds credentials.TransportCredentials
	tlsCreds, err := NewCredentialsFromPEM(Cert, "")
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if tlsCreds == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

// Error path: Tests that NewCredentialsFromPEM returns an error for an invalid
// certificate.
func TestNewCredentialsFromPEM_InvalidCertificateError(t *testing.T) {
	_, err := NewCredentialsFromPEM("this is a cert yes", "")
	if err == nil {
		t.Errorf("Failed to return error for invalid certificate")
	}
}

// Happy path
func TestNewPublicKeyFromFile(t *testing.T) {
	path := testkeys.GetTestCertPath()
	var p *rsa.PublicKey
	p, err := NewPublicKeyFromFile(path)
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if p == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

// Error path: Tests that NewPublicKeyFromFile returns os.ErrNotExist for a cert
// path that points to a file that does not exist.
func TestNewPublicKeyFromFile_BadCertPathError(t *testing.T) {
	path := testkeys.GetTestCertPath() + "abc"
	_, err := NewPublicKeyFromFile(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Did not receive expected error for an invalid cert path."+
			"\nexpected: %v\nreceived: %+v", os.ErrNotExist, err)
	}
}

// Error path: Tests that NewPublicKeyFromFile returns an error for an invalid
// certificate
func TestNewPublicKeyFromFile_BadCertError(t *testing.T) {
	_, err := NewPublicKeyFromFile(testkeys.GetTestKeyPath())
	if err == nil {
		t.Errorf("Failed to get error when passing a key instead of a cert.")
	}
}

// Happy path
func TestNewPublicKeyFromPEM(t *testing.T) {
	path := testkeys.GetTestCertPath()
	filePath := getFullPath(path)
	certBytes, err := utils.ReadFile(filePath)
	if err != nil {
		t.Errorf("Failed to read public key file at %s: %+v", filePath, err)
	}

	var p *rsa.PublicKey
	p, err = NewPublicKeyFromPEM(certBytes)
	if err != nil {
		t.Errorf("Error setting tls credentials: %+v", err)
	}
	if p == nil {
		t.Errorf("Failed to set tls credentials")
	}
}

// Error path: Tests that NewPublicKeyFromPEM returns an error for invalid cert
// bytes
func TestNewPublicKeyFromPEM_Error(t *testing.T) {
	path := getFullPath(testkeys.GetTestKeyPath())
	keyBytes, err := utils.ReadFile(path)
	if err != nil {
		t.Errorf("Failed to read public key file at %s: %+v", path, err)
	}

	_, err = NewPublicKeyFromPEM(keyBytes)
	if err == nil {
		t.Errorf("Expected error when passing key bytes instead of cert bytes.")
	}
}
