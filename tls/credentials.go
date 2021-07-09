////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package tls contains wrapper functions for creating GRPC credentials.
// It also implements RSA key parsing
package tls

import (
	gorsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/utils"
	"google.golang.org/grpc/credentials"
	"strings"
	"time"
)

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

// NewCredentialsFromPEM creates a TransportCredentials object out of a string
// Accepts a nameOverride for use in test environments
func NewCredentialsFromPEM(certificate string, nameOverride string) (credentials.TransportCredentials, error) {
	if nameOverride == "" {
		jww.WARN.Printf("Failure to provide name override can result in" +
			" TLS connection timeouts")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certificate)) {
		jww.ERROR.Printf("Error appending certs to cert pool: %+v", certificate)
		return nil, errors.New("failed to append cert to pool")
	}
	return credentials.NewClientTLSFromCert(pool, nameOverride), nil
}

// NewCredentialsFromFile creates a TransportCredentials object from the contents of a file
// Accepts a nameOverride for use in test environments
func NewCredentialsFromFile(filePath string, nameOverride string) (credentials.TransportCredentials, error) {
	if nameOverride == "" {
		jww.WARN.Printf("Failure to provide name override can result in" +
			" TLS connection timeouts")
	}

	filePath = getFullPath(filePath)
	result, err := credentials.NewClientTLSFromFile(filePath, nameOverride)
	if err != nil {
		jww.ERROR.Printf("Could not load TLS keys: %s", err)
		return nil, err
	}
	return result, nil
}

// NewPublicKeyFromFile reads the contents of a file and uses it to create a PublicKey object
func NewPublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	//Pull the cert from the file
	filePath = getFullPath(filePath)
	certBytes, err := utils.ReadFile(filePath)
	if err != nil {
		jww.ERROR.Printf("Failed to read public key file at %s: %+v", filePath, err)
		return nil, err
	}

	//Decode the certificate
	block, _ := pem.Decode(certBytes)

	//Create the cert object
	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		jww.ERROR.Printf("Error parsing PEM into certificate: %+v", err)
		return nil, err
	}

	//Pull the public key from the cert object
	rsaPublicKey := cert.PublicKey.(*gorsa.PublicKey)
	return &rsa.PublicKey{
		PublicKey: *rsaPublicKey,
	}, nil
}

// NewPublicKeyFromPEM accepts a PEM certificate block in []byte format
// and returns a *rsa.PublicKey object
func NewPublicKeyFromPEM(certPEMblock []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certPEMblock)

	//Parse the certificate
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		jww.ERROR.Printf("Error parsing PEM into certificate: %+v", err)
		return nil, err
	}
	timeTest := time.Now()
	if timeTest.After(cert.NotAfter) {
		return nil, errors.Errorf("Cannot load cert, it is expired: %s", cert.NotAfter)
	}
	if timeTest.Before(cert.NotBefore) {
		return nil, errors.Errorf("Cannot load cert, it is not yet valid: %s", cert.NotBefore)
	}

	//From the cert, get it's public key
	rsaPublicKey := cert.PublicKey.(*gorsa.PublicKey)
	return &rsa.PublicKey{
		PublicKey: *rsaPublicKey,
	}, nil
}
