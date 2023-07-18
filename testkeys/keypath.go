////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package testkeys

import (
	"path/filepath"
	"runtime"
)

func getDirForFile() string {
	// Get the filename we're in
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Dir(currentFile)
}

// GetTestCertPath returns a file path to a cert that is used to cover TLS
// connection code in tests.
func GetTestCertPath() string {
	return filepath.Join(getDirForFile(), "cmix.rip.crt")
}

// GetTestKeyPath returns a file path to a key that is used to cover TLS
// connection code in tests.
func GetTestKeyPath() string {
	return filepath.Join(getDirForFile(), "cmix.rip.key")
}
