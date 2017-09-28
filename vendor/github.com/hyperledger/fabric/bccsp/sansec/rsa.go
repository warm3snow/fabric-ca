/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sansec

import (
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
)

//const RSAKeyLen = 32

func (csp *impl) signRSA(k rsaPrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	fmt.Printf("k.ski %v\n k.SKI() %v\n", k.ski, k.SKI())
	sig, err := csp.signP11RSA(k.SKI(), digest)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (csp *impl) verifyRSA(k rsaPublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return csp.verifyP11RSA(k.ski, digest, signature)
}
