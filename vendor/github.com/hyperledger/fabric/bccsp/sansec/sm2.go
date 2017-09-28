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
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/warm3snow/gmsm/sm2"
)

type sm2Signature struct {
	R, S *big.Int
}

//const SM2KeyLen = 32

func (csp *impl) signSM2(k sm2PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	r, s, err := csp.signP11SM2(k.ski, digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
}

func (csp *impl) verifySM2(k sm2PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	var sig sm2Signature
	_, err = asn1.Unmarshal(signature, &sig)
	if err != nil {
		return false, fmt.Errorf("Failed unmarshaling signature [%s]", err)
	}

	if csp.SoftVerify {
		fmt.Println("SoftVerify .........")
		return sm2.Verify(k.pub, digest, sig.R, sig.S), nil
	} else {
		fmt.Println("PKCS11 Verify .........")
		return csp.verifyP11SM2(k.ski, digest, sig.R, sig.S, k.pub.Curve.Params().BitSize/8)
	}
}
