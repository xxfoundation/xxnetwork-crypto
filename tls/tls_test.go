////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package tls

import (
	"strings"
	"testing"
)

const DsaCert = `-----BEGIN CERTIFICATE-----
MIIC+zCCArkCCQDn3tWcVrDYvDALBglghkgBZQMEAwIwYTELMAkGA1UEBhMCeHgx
CzAJBgNVBAgMAnh4MQswCQYDVQQHDAJ4eDELMAkGA1UECgwCeHgxCzAJBgNVBAsM
Anh4MQswCQYDVQQDDAJ4eDERMA8GCSqGSIb3DQEJARYCeHgwHhcNMjEwNzA2MjEw
MDEyWhcNMzEwNzA0MjEwMDEyWjBhMQswCQYDVQQGEwJ4eDELMAkGA1UECAwCeHgx
CzAJBgNVBAcMAnh4MQswCQYDVQQKDAJ4eDELMAkGA1UECwwCeHgxCzAJBgNVBAMM
Anh4MREwDwYJKoZIhvcNAQkBFgJ4eDCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQDj
QcUKVDwFwzKfprlcrGNy0pNMeot1ljin6Kb6XHOjDNgEGgJPWFXhO/iJOt3l5YrP
olTTh2+muuBrTtpsYtyOfDs0qMBRy+BAOeMj/nkGoJurq6HV9A7CSOPZc8RWtL64
gRAQ/sBUnpreikCSRBu59SAMyMI2xRP23OY1A7nSJwIVALNkmBm2+NuB8xLqJjvS
pqBmEAWZAoGBAJwscB1zabWrfyu/UPg7iAWFQnwfsC6B3m5oU31tkU5/iGhEFfzH
Wm7aBzpEYgA7mXmBpLfXxWpTSZ8Oe/pkvIpuTAJfxwsIRvX6zJKK1ta9m2pBVkY6
OChghSqPwegdYg6cuhbAhGJ77kiV0j2u0QZcxXMFZ4ehr0ip01eV+QahA4GEAAKB
gHvZNPkloprW5RXDHaiW3ZUuIGGucXf1bczCBtDNtznCNr+ypSxHGK3MknKmCLvx
B9DMbVJ0ptZ+FwuVGJAEq4oY6X5ZioT1zIm5lPrWlt1ttIzkeOaYsfGKlHmx8eg1
TUjoSEWtMfO3wsC+46BYH3qxDfM87sEeywmCCnIQVmT3MAsGCWCGSAFlAwQDAgMv
ADAsAhQXbBkoqMSCY715k2NnE3UvzpRmggIURGfA7EuxTAF3U7tYcPrVdISbnBk=
-----END CERTIFICATE-----
`

const Cert = `-----BEGIN CERTIFICATE-----
MIICOTCCAaICCQDpAv5PYUJpOTANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJ4
eDELMAkGA1UECAwCeHgxCzAJBgNVBAcMAnh4MQswCQYDVQQKDAJ4eDELMAkGA1UE
CwwCeHgxCzAJBgNVBAMMAnh4MREwDwYJKoZIhvcNAQkBFgJ4eDAeFw0yMTA3MDYy
MDMzNTVaFw0zMTA3MDQyMDMzNTVaMGExCzAJBgNVBAYTAnh4MQswCQYDVQQIDAJ4
eDELMAkGA1UEBwwCeHgxCzAJBgNVBAoMAnh4MQswCQYDVQQLDAJ4eDELMAkGA1UE
AwwCeHgxETAPBgkqhkiG9w0BCQEWAnh4MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDakqY2CW7VtTw7pElKHCs4EQ92qT+2y58f3T5euza3QP6kr/3xINa3UXP7
NfXhUgVZ7N0sHjYFZXxqctalcEKW/FHmyDVKaz6IOyiH0g0g9PdsofaHjK1QXzS5
JA63hSdVObfkPuIcqlvBMovxzlHCAqdafkjEeqQoBeuUgRrMPQIDAQABMA0GCSqG
SIb3DQEBCwUAA4GBAEAp53K74s54oBSpLFLYl79MU+5+J2XogRhEhOhj7qiAdqPz
qpwGhWSztpERThUvgcD8p5wdlkXpqkB70cO6yILEoHk5XAohb3tK0tHXz3T8P4cU
Gd1lD8wEtJvFlgfJJw7aOfRxDfnu+xO47RksTNOfz3CmGVpMX58jhhVaqIGO
-----END CERTIFICATE-----
`

const PrivateKeyPKCS1 = `-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANqSpjYJbtW1PDuk
SUocKzgRD3apP7bLnx/dPl67NrdA/qSv/fEg1rdRc/s19eFSBVns3SweNgVlfGpy
1qVwQpb8UebINUprPog7KIfSDSD092yh9oeMrVBfNLkkDreFJ1U5t+Q+4hyqW8Ey
i/HOUcICp1p+SMR6pCgF65SBGsw9AgMBAAECgYEAlTuPdFGYdR1a1LXkvE7jS1KK
plAEioAYUx8x2GgmgZREyJjI33u2Xk+kyp4bFQ51TOKmV9sAs0qJWfyyhR5St5R/
62tPbza0OR0jCZh7mwpivd3XnPxvWKpjdpjVCvD5lMnjEp+7+zjOBEu1E6Y5dlm3
dGcHfp1OiLG+ru5LedkCQQD4rmmF343TY5QeuoIDN+j68a09MHZAfIWtYY/psXPa
LLRenRhLj9wNSQTsHiXAvOQ0C3NiaOFtF2XQNQqUH8/DAkEA4QFlsTfM669th5Yu
YqNydWgdvnkufJ/MnlOJ6g1ruj152hZMAkAH2t3GHfvVtuNHFN3AvWgwvfM/dNI8
o20z/wJBAJCOUijP2tGWgPOb1xen2HaHJfz7vsGdoNc4bz+ZN48LjY2yI/1IktHm
MEZRAAEZzE20mk4KSX/wqe5t5shT9aECQCAXNey/m59lpsZ2uejhjNqH3e4jlGi7
1dAi9AGIpnuqdu2OzopnnXcuuCngmAt8gM/ODMY2zPTac4tyzKk2UvsCQQCAulo6
uwne3AGKkz9N1AWgAvqy5IsE5yHF09wayUn+0raSORPBX29MqEAzwGoJafcbvp4l
XHDTEkW8eu6II8iz
-----END PRIVATE KEY-----
`

//An ECDSA PKCS8 private key
const ECDSA_PRIVATEKEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVTfeWQAwaQ2fX1RM
rzhicau6dkfnTZmRXMhSgHn1O/2hRANCAAQaG9n2s+E/HxSbEx4xn9lKQkOL7MzS
XSlHvlSAyk3CY3kfptxz2n6ybXO0tKgmQ7D3JqZ7fhRxCmqOSSqHftWc
-----END PRIVATE KEY-----
`

const RSAPrivateKeyPKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0evor0jCNWanE
GfkvyLno7GxsmY7fTN50BY12fIpJkaPbO+e3xheJkj4/aS4zyznDjqjp7z5X0W9u
S9l/fvfi4F87E1GYAhUQFeI8XkETYz8fyAUb9xhghWiC6h4dJoctX9G+2PYW7zTW
GL6E0PLQdQX/7yIfq5qQMMoWogg+UhosmbaRaHY9jpYwRnz24VYfzqtKQDqIhAQi
hHtU3lLVVeo+YUwGTektsMz5ZytfGqFIxuwAEf6DXSFHYKleFcfE3Qh25dDSzlIB
HZzBYweTQ1/LuwPciQ0uJiiRhsy0vZXd7cYoumrQ4uxNqBK2Lz4i1/E4hFs31hWT
x5PDcaovAgMBAAECggEBAKq8uFSiaNof29GvvKQu4Wlv2Ha4ooevIbdi1VwlH3HP
vNKXDnQ1i2jTF95HM7U96ayOFlAQy8qqUB9o1B6gUAOqvYyWjxcdyS1Jdpgjlq6v
sjTvtZ2qGb6eFqvarZhoLXOIdVV1zQEPVM3B5OKjBUKdoopngMGzRupnrZbRvLiu
vbMrXwjvWGSA+CX8LsXfM21WgDqtxlZkix2L86ZhW3H80WFp2isgjq3T0FNKV4Ng
TX6InUccZ78X+tqfumfYqsFYnbarEegJb9PMnLCeKEHt5Xo42G0nLgMCvYGFUGnC
pUo7OSi56y18UP6vXeeHBP2S0/EUqrUvOliVFxAnvBkCgYEA5EsttJQz1t8MZT8e
oE6bcfWRpQseMt7UfPhUBkGVabBNbcVwk+3G9QKUjkJfaojt9rI4M/7Ed8ezc3Od
FWT1oyIdTGH6VwJZ15eI3PCBC9uVlnphywEOqeqZhZFdxGlAaohlYVncS4tDBQZa
RVmGVLp7cHr0tAhz9Y7S8uv5N3MCgYEAymJLf5+4n9UOwFM9t+AFJEI+yQHYPiys
bdc17GaaC0p3asUgFwHiYp23L0WORqdTlFuTti1SAchDBpRmioHC4oqL+efRjhu9
S57ZRyVuSVPi2ySBU0q1mS09qVRXSW5c8hFyKkyIR1GEvYAT2Q1HOCFvwkYWWFtp
goURPHQ6e1UCgYAxm4h+AepV2bgW1CVyjkJG/Ca+53CTe0pPMaMIjP3LrozUup+g
9X1TRlFDrHaRbtnOzqFZ4xWMNa/v+YJ74Klj3ojhTTUZ7R/askoCQJy6F+gkf8l6
VGt8Tsc3eAQZJwnhXGwzQFSXcdaJY/z/rtl61d727TD5YhDYnkWGlfJcswKBgAEU
sU6HLdc8rg185FF9Esn0yJ0OM3dxiaI0igcvLRduWGDrmJZG3kykhvvrpSzfa+TY
8FsCtvNnfGQmmr2Wn9HR55l4EXhu0X375TEqFAK0Pfvpn/8v4PRmd3PWDXlI65on
WbK8IeYvm0Pf0TtRhNXZ59zjvu7N3ixiRYtLG5zZAoGAfRs2nTzAT9xl8jgrG8o+
Ht2ZSDbcmqcD+7GWCoR/aro23EYMV6DZv1HvC73Gr6ofmDZ/H+i1kuRhHawOQRJt
P/MjtbfUUWKnjVfxrrpI+IsaaHHiSvjeYi2/ATtCYF4GL6lfR2DpBXTF8cV78DYf
T3UnhGjI6VSYfYYJIhqwaqk=
-----END PRIVATE KEY-----
`

const ed25519Key = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOCWuyHuYHEEUa334Qriq9PK9fwwtda1YJrjzqWwY9o6
-----END PRIVATE KEY-----`
const RSAExpiredCertificate = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`
const DSAExpiredCertificate = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`
const RSANotYetValidCert = `-----BEGIN CERTIFICATE-----
MIICFjCCAcCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQ
dHkgTHRkMQ0wCwYDVQQDDAR0ZXN0MCAYDzIyMjEwMTAxMTIwMDAwWhcNMjIwNzIx
MjMzNjQwWjBUMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8G
A1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYDVQQDDAR0ZXN0MFww
DQYJKoZIhvcNAQEBBQADSwAwSAJBAMFNOHh5qTiePqdxgEhXOLe0masyGpYKP3Mj
S4EOGUKWOdb+y1HT1k1Sfc3M+R4NbtWbAFTPa3mGMvRxldwCQKkCAwEAAaN7MHkw
CQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2Vy
dGlmaWNhdGUwHQYDVR0OBBYEFPqTlChzDJhnkE5tkDODo6pLubWIMB8GA1UdIwQY
MBaAFPqTlChzDJhnkE5tkDODo6pLubWIMA0GCSqGSIb3DQEBCwUAA0EAZR0Fu2IV
BOUPszTMjBUYTnrAdb1fhThCWrqZWJIOe721UXbuT6VYciehCBzqUqz2hQu1bAvx
oARYVHp/Gzmk2g==
-----END CERTIFICATE-----`

//Error path: pass an empty file into the loaders
func TestEmptyFile(t *testing.T) {
	empty := ""
	//Pass the empty string into loading the certificate
	_, err := LoadCertificate(empty)
	if err == nil {
		t.Error("Generated a certificate from an empty file!")
	}

	//Pass the empty string into loading the private key
	_, err = LoadRSAPrivateKey(empty)
	if err == nil {
		t.Error("Generated a private key from an empty file!")
	}
}

//Error path: Pass incorrectly formated contents into the loaders
func TestLoadIncorrectly(t *testing.T) {
	//Pass the private key into the certificate loader
	_, err := LoadCertificate(PrivateKeyPKCS1)
	if err == nil {
		t.Error("Failed to detect passing in a non-certificate into LoadCertificate")
	}
	//Pass the request into the private key loader
	_, err = LoadRSAPrivateKey(Cert)
	if err == nil {
		t.Error("Failed to detect passing a non-private key into LoadRSAPrivateKey")
	}
}

//Happy Path: pass everything as intended. No errors should occur in this test
func TestTLS_SmokeTest(t *testing.T) {

	// Load the PKCS#1 Key
	privKey, err := LoadRSAPrivateKey(PrivateKeyPKCS1)
	if err != nil {
		t.Errorf("Unable to load private key: %+v", err.Error())
	}
	if privKey == nil || err != nil {
		t.Error("Failed to load a correctly formatted private key")

	}

	cert, err := LoadCertificate(Cert)
	if err != nil {
		t.Error(err.Error())
	}

	if cert == nil || err != nil {
		t.Error("Failed to load a correctly formatted Certificate")
	}

	//Load the PKCS#8 private key
	privKey, err = LoadRSAPrivateKey(RSAPrivateKeyPKCS8)
	if err != nil {
		t.Errorf("%+v", err)
	}

	if privKey == nil {
		t.Errorf("Failed to pull private key from PEM-encoded string")
	}

}

//Error path: Passes in an ecdsa pkcs#8 private key.
func TestTLS_IncorrectPrivateKey(t *testing.T) {
	_, err := LoadRSAPrivateKey(ECDSA_PRIVATEKEY)
	if err == nil {
		t.Errorf("Expected Error case: Should not load key of type ECDSA")

	}

	_, err = LoadRSAPrivateKey(ed25519Key)
	if err == nil {
		t.Errorf("Expected Error case: Should not load key of type ed25519")
	}
}

func TestExtractPublicKeyFromCert(t *testing.T) {
	x509Cert, err := LoadCertificate(Cert)
	if err != nil {
		t.Errorf("Failed to load certificate: %+v", err)
	}

	_, err = ExtractPublicKey(x509Cert)
	if err != nil {
		t.Errorf("Failed to extract public key from certificate: %+v", err)
	}

	dsaCert, err := LoadCertificate(DsaCert)
	if err != nil {
		t.Errorf("Failed to load certificate: %+v", err)
	}
	_, err = ExtractPublicKey(dsaCert)
	if err != nil {
		return
	}

	t.Errorf("Expected error case, should not return a DSA key!")
}

//Tests for DSA cert has expired
func TestExpiredDSACerts(t *testing.T) {
	//Loads DSA key
	_, err := LoadCertificate(DSAExpiredCertificate)
	if err == nil {
		t.Error("Failed to detect passing in a non-certificate into LoadCertificate")
	}
	expErr := "LoadCertificate: Cannot load cert, it is expired on the date"
	//Turns the error into an error message
	if !strings.HasPrefix(err.Error(), expErr) {
		t.Errorf("DSA cert should be expired: %v", err)
	}
}

//Tests if RSA cert has expired
func TestExpiredRSACerts(t *testing.T) {
	//Loads RSA cert
	_, err := LoadCertificate(RSAExpiredCertificate)
	if err == nil {
		t.Error("Failed to detect passing in a non-certificate into LoadCertificate")
	}
	//Turns the error into an error message
	if strings.HasPrefix("Cannot load RSA cert, it is expired", err.Error()) {
		t.Error("Cannot load RSA cert, it is expired")
	}
}
