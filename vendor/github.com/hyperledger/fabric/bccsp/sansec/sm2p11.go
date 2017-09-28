/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	"github.com/warm3snow/pkcs11"
	"github.com/warm3snow/gmsm/sm2"
)

var (
	namedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// Look for an EC key by SKI, stored in CKA_ID
//For EC SM2 and RSA
func (csp *impl) getSM2Key(ski []byte) (pubKey *sm2.PublicKey, isPriv bool, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)
	isPriv = true
	_, err = findKeyPairFromSKI(p11lib, session, ski, isPrivateKey)
	if err != nil {
		isPriv = false
		logger.Debugf("Private key not found [%s] for SKI [%s], looking for Public key", err, hex.EncodeToString(ski))
	}

	publicKey, err := findKeyPairFromSKI(p11lib, session, ski, isPublicKey)
	if err != nil {
		return nil, false, fmt.Errorf("Public key not found [%s] for SKI [%s]", err, hex.EncodeToString(ski))
	}

	//ecPoint func returned marshaledOid is nil, FIXME
	ecpt, _, err := ecPoint(p11lib, session, *publicKey)
	if err != nil {
		return nil, false, fmt.Errorf("Public key not found [%s] for SKI [%s]", err, hex.EncodeToString(ski))
	}

	curve := sm2.P256Sm2()
	//add DER encoding
	ecpt = append([]byte{0x04}, ecpt...)
	x, y := elliptic.Unmarshal(curve, ecpt)
	if x == nil {
		return nil, false, fmt.Errorf("Failed Unmarshaliing Public Key")
	}

	pubKey = &sm2.PublicKey{curve, x, y}
	return pubKey, isPriv, nil
}

func (csp *impl) generateSM2Key(ephemeral bool) (ski []byte, pubKey *sm2.PublicKey, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	id := nextIDCtr()
	idText := id.Text(16)
	label := fmt.Sprintf("SM2SignKey%s", idText)

	pubkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}

	prvkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}

	mech_t := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_IBM_SM2_KEY_PAIR_GEN, nil),
	}

	pub, prv, err := p11lib.GenerateKeyPair(session, mech_t, pubkey_t, prvkey_t)

	if err != nil {
		return nil, nil, fmt.Errorf("P11: keypair generate failed [%s]\n", err)
	}

	ecpt, _, err := ecPoint(p11lib, session, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get EC_Point %v", err)
	}

	hash := sha256.Sum256(ecpt)
	ski = hash[:]
	// set CKA_ID of both keys to SKI(public key)
	setski_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
	}

	//logger.Infof("Generated new P11 key, SKI %x\n", ski)
	err = p11lib.SetAttributeValue(session, pub, setski_t)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: set-ID-to-SKI[public] failed [%s]\n", err)
	}

	err = p11lib.SetAttributeValue(session, prv, setski_t)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: set-ID-to-SKI[private] failed [%s]\n", err)
	}

	curve := sm2.P256Sm2()
	//add der encoding
	ecpt = append([]byte{0x04}, ecpt...)
	x, y := elliptic.Unmarshal(curve, ecpt)
	if x == nil {
		return nil, nil, fmt.Errorf("Failed Unmarshaling Public Key")
	}
	pubKey = &sm2.PublicKey{Curve: curve, X: x, Y: y}

	return ski, pubKey, nil
}

func (csp *impl) signP11SM2(ski []byte, msg []byte) (R, S *big.Int, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	privateKey, err := findKeyPairFromSKI(p11lib, session, ski, isPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Private key not found [%s]\n", err)
	}

	err = p11lib.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_IBM_SM2, nil)}, *privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Sign-initialize  failed [%s]\n", err)
	}

	sig, err := p11lib.Sign(session, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: sign failed [%s]\n", err)
	}

	R, S = new(big.Int), new(big.Int)
	R.SetBytes(sig[:len(sig)/2])
	S.SetBytes(sig[len(sig)/2:])

	return R, S, nil
}

func (csp *impl) verifyP11SM2(ski, msg []byte, R, S *big.Int, byteSize int) (valid bool, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	publicKey, err := findKeyPairFromSKI(p11lib, session, ski, isPublicKey)
	if err != nil {
		return false, fmt.Errorf("Public key not found [%s]\n", err)
	}

	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, byteSize*2)
	copy(sig[byteSize-len(r):byteSize], r)
	copy(sig[2*byteSize-len(s):], s)

	err = p11lib.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_IBM_SM2, nil)}, *publicKey)
	if err != nil {
		return false, fmt.Errorf("PKCS11: Verify-initialize [%s]\n", err)
	}
	err = p11lib.Verify(session, msg, sig)
	if err == pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("PKCS11: Verify failed [%s]\n", err)
	}

	return true, nil
}

func (csp *impl) importSM2Key(privKey, ecPt []byte, ephemeral bool, isPrivate bool) (ski []byte, err error) {
	fmt.Printf("privkey length: %d, ecPt length: %d\n", len(privKey), len(ecPt))

	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	id := nextIDCtr()
	index := int(50 - id.Int64())
	label := fmt.Sprintf("SM2SignKey%s", strconv.Itoa(index))

	//marshalOid, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1})
	/*
		marshalOid, err := asn1.Marshal(namedCurveP256SM2)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal OID[%s]", err.Error())
		}
	*/

	var keyTemplate []*pkcs11.Attribute
	if isPrivate == isPublicKey {
		logger.Debug("Importing Public SM2 Key")

		hash := sha256.Sum256(ecPt)
		ski = hash[:]
		//add DER encoding for CKA_EC_POINT
		//ecPt = append([]byte{0x04, byte(len(ecPt))}, ecPt...)

		keyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SM2),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),

			//pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshalOid),
			pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
		}
	} else { // isPrivateKey

		ski, err = csp.importSM2Key(nil, ecPt, ephemeral, isPublicKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to import private SM2 Key [%s]\n", err)
		}

		logger.Debugf("Importing Private SM2 Key [%d]\n%s\n", len(privKey)*8, hex.Dump(privKey))
		keyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SM2),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, privKey),

			pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
		}
	}
	keyHandle, err := p11lib.CreateObject(session, keyTemplate)
	if err != nil {
		return nil, fmt.Errorf("P11: keypair generate failed [%s]\n", err)
	}
	_ = keyHandle

	return ski, nil
}

/*
//Q' = Q + k.G (Q and k is known, G is stored in HSM)
//Format: input(Q, k), output(Q')
func (csp *impl) deriveSM2Key(ecpt, expVal []byte, ephemeral, isPrivate bool) (dski []byte, pub *sm2.PublicKey, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	//mechDeriveKey2.mechanism = CKM_SM2_MULT_ADD for PublicKey
	//mechDeriveKey1.mechanism = CKM_SM2_MOD_MULT_ADD for PrivateKey
	if isPrivate == isPublicKey {
		logger.Debugf("Deriving Public SM2 Key.......")
		ski, hkey, err := importSM2Key(nil, ecpt, ephemeral, isPublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to import public SM2 key [%s]\n", err)
		}
		//derive key
		mech_t := []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_SM2_MULT_ADD, derivPubKeyParams(ecpt, expVal)),
		}
		attrs := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		}
		drvPub, err := p11lib.DeriveKey(session, mech_t, hkey, attrs)
		if err != nil {
			return nil, nil, fmt.Errorf("P11: SM2 PublicKey Derived failed [%v]", err)
		}
		//set ski
		decpt, oid, err := ecPoint(p11lib, session, drvPub)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to get EC_Point [%v]", err)
		}
		logger.Debugf("CKA_EC_POINT drv_ecpt [%v]\nCKA_EC_PARAMS oid [%v]", decpt, oid)
		hash := sha256.Sum256(decpt)
		dski = hash[:]
		setski_t := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, dski),
		}
		err = p11lib.SetAttributeValue(session, drvPub, setski_t)
		if err != nil {
			return nil, nil, fmt.Errorf("P11: set-ID-to-SKI[public] failed [%s]\n", err)
		}
		logger.Debugf("Deriving SM2 Public Key success!")
		return dski, decpt, nil
	} else {
		logger.Debugf("Deriving Private SM2 Key.......")
		//first to derive the publickey to get the ski, it maybe not necessary
		dski, decpt, err := deriveSM2Key(nil, ecpt, expVal, ephemeral, isPublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("P11: SM2 PrivateKey Derived failed [%v]", err)
		}
		pri, err := findKeyPairFromSKI(p11lib, session, ski, isPrivateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("P11: Can't find Private SKI[%s], err [%v]\n", hex.EncodeToString(ski), err)
		}
		//derive key
		mech_t := []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_SM2_MOD_MULT_ADD, expVal),
		}
		attrs := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		}
		drvPri, err := p11lib.DeriveKey(session, mech_t, *pri, attrs)
		if err != nil {
			return nil, nil, fmt.Errorf("P11: SM2 PrivateKey Derived failed [%v]", err)
		}
		//set ski
		setski_t := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, dski),
		}
		err = p11lib.SetAttributeValue(session, drvPri, setski_t)
		if err != nil {
			return nil, nil, fmt.Errorf("P11: set-ID-to-SKI[private] failed [%s]\n", err)
		}
		logger.Debugf("Deriving SM2 Private Key success!")
		return dski, decpt, nil
	}
	return nil, nil, errors.New("Failed to deriveSM2Key...")
}

var pad1 = []byte{0x30, 0x81, 0x8c, 0x30, 0x44, 0x02, 0x20}
var pad2 = []byte{0x30, 0x44, 0x02, 0x20}
var pad3 = []byte{0x02, 0x20}

func (csp *impl) derivPubKeyParams(ecpt, expVal []byte) (params []byte) {
	c := sm2.P256Sm2()
	val := make([]byte, 64)
	x, y := c.ScalarBaseMult(expVal)
	copy(val[0:32], x.Bytes())
	copy(val[32:], y.Bytes())
	params := make([]byte, 143)

	//add pad
	copy(params[0:], pad1)
	copy(params[39:], pad3)
	copy(params[73:], pad2)
	copy(params[109:], pad3)
	//add Q
	copy(params[7:], ecpt[:32])
	copy(params[41:], ecpt[32:])
	//add k.G
	copy(params[77:], val[:32])
	copy(params[111:], val[32:])
	return params
}
func (csp *impl) derivPriKeyParams(privKey, expVal []byte) (params []byte) {
	params := make([]byte, 70)
	//add pad
	copy(params[0:], pad2)
	copy(params[36:], pad3)
	//add a
	copy(params[4:], privKey)
	//add k
	copy(params[38:], expVal)

	return params
}
*/
