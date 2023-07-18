////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package tls contains wrapper functions for creating GRPC credentials.
// It also implements RSA key parsing.
package tls

import (
	gorsa "crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/mitchellh/go-homedir"
	jww "github.com/spf13/jwalterweatherman"
	"google.golang.org/grpc/credentials"

	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/utils"
)

// minTlsVersion is the minimum TLS version.
// In this case, LS protocol version 1.3. When using TLS 1.3 the tls.Config's
// Ciphersuites field is ignored as of Go 1.17.
var minTlsVersion uint16 = tls.VersionTLS13

// acceptedCurves are the accepted elliptic curve groups accepted by
// the network.
var acceptedCurves = []tls.CurveID{
	tls.X25519,
}

// NewCredentialsFromPEM creates a TransportCredentials object out of a string.
// Accepts a nameOverride for use in test environments.
func NewCredentialsFromPEM(certificate string,
	nameOverride string) (credentials.TransportCredentials, error) {
	if nameOverride == "" {
		jww.WARN.Printf("Failure to provide name override can result in" +
			" TLS connection timeouts")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certificate)) {
		jww.ERROR.Printf("Error appending certs to cert pool: %+v", certificate)
		return nil, errors.New("failed to append cert to pool")
	}
	return credentials.NewTLS(&tls.Config{
		ServerName:       nameOverride,
		RootCAs:          pool,
		MinVersion:       minTlsVersion,
		CurvePreferences: acceptedCurves,
	}), nil
}

// NewCredentialsFromFile creates a TransportCredentials object
// from the contents of a file. Accepts a nameOverride for use in
// test environments.
func NewCredentialsFromFile(filePath string,
	nameOverride string) (credentials.TransportCredentials, error) {
	if nameOverride == "" {
		jww.WARN.Printf("Failure to provide name override can result in" +
			" TLS connection timeouts")
	}

	// Read file
	filePath = getFullPath(filePath)
	b, err := utils.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Construct cert pool
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(b) {
		return nil, errors.New("credentials: failed to append certificates")
	}

	return credentials.NewTLS(&tls.Config{
		ServerName:       nameOverride,
		RootCAs:          cp,
		MinVersion:       minTlsVersion,
		CurvePreferences: acceptedCurves,
	}), nil
}

// NewPublicKeyFromFile reads the contents of a file and uses it
// to create a PublicKey object.
func NewPublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	// Pull the cert from the file
	filePath = getFullPath(filePath)
	certBytes, err := utils.ReadFile(filePath)
	if err != nil {
		jww.ERROR.Printf("Failed to read public key file at %s: %+v",
			filePath, err)
		return nil, err
	}

	// Decode the certificate
	block, _ := pem.Decode(certBytes)

	// Create the cert object
	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		jww.ERROR.Printf("Error parsing PEM into certificate: %+v", err)
		return nil, err
	}

	// Pull the public key from the cert object
	rsaPublicKey := cert.PublicKey.(*gorsa.PublicKey)
	return &rsa.PublicKey{
		PublicKey: *rsaPublicKey,
	}, nil
}

// NewPublicKeyFromPEM accepts a PEM certificate block in []byte format
// and returns a *rsa.PublicKey object.
func NewPublicKeyFromPEM(certPemBlock []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certPemBlock)

	// Parse the certificate
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		jww.ERROR.Printf("Error parsing PEM into certificate: %+v", err)
		return nil, err
	}

	// From the cert, get it's public key
	rsaPublicKey := cert.PublicKey.(*gorsa.PublicKey)
	return &rsa.PublicKey{
		PublicKey: *rsaPublicKey,
	}, nil
}

// getFullPath is a helper method which resolves ~ used in relative paths
func getFullPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			jww.ERROR.Printf("Unable to locate home directory: %v", err)
		}
		// Append the home directory to the path
		return home + strings.TrimLeft(path, "~")
	}
	return path
}
