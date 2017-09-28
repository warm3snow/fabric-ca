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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/warm3snow/pkcs11"
)

func (csp *impl) pubParams(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (n, e []byte, err error) {
	attr_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attr, err := p11lib.GetAttributeValue(session, key, attr_t)
	if err != nil {
		return nil, nil, fmt.Errorf("PKCS11: get pubKey params err [%s]", err)
	}
	for _, a := range attr {
		if a.Type == pkcs11.CKA_MODULUS {
			n = a.Value
		} else if a.Type == pkcs11.CKA_PUBLIC_EXPONENT {
			e = a.Value
		}
	}
	if n == nil || e == nil {
		return nil, nil, errors.New("RSA Public Key Object Attributes not found")
	}
	return n, e, nil
}

func (csp *impl) privParams(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (n, e, d, p, q []byte, err error) {
	attr_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, nil),
	}
	attr, err := p11lib.GetAttributeValue(session, key, attr_t)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("PKCS11: get privKey params err [%s]", err)
	}
	for _, a := range attr {
		if a.Type == pkcs11.CKA_MODULUS {
			n = a.Value
		} else if a.Type == pkcs11.CKA_PUBLIC_EXPONENT {
			e = a.Value
		} else if a.Type == pkcs11.CKA_PRIVATE_EXPONENT {
			d = a.Value
		} else if a.Type == pkcs11.CKA_PRIME_1 {
			p = a.Value
		} else if a.Type == pkcs11.CKA_PRIME_2 {
			q = a.Value
		}
	}
	if n == nil || e == nil || d == nil || p == nil || q == nil {
		return nil, nil, nil, nil, nil, errors.New("RSA Private Key Object Attributes not found")
	}
	return n, e, d, p, q, nil
}

// Look for an RSA key by SKI, stored in CKA_ID
// This function can probably be addapted for both EC, SM2 and RSA keys.
func (csp *impl) getRSAKey(ski []byte) (pubKey *rsa.PublicKey, isPriv bool, err error) {
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

	var N *big.Int
	var E int
	n, e, err := csp.pubParams(p11lib, session, *publicKey)
	if err != nil {
		return nil, false, fmt.Errorf("Get RSA key from publickey err [%s]", err)
	}
	N = new(big.Int).SetBytes(n)
	E = int(new(big.Int).SetBytes(e).Int64())
	pubKey = &rsa.PublicKey{N, E}

	return pubKey, isPriv, nil
}

func (csp *impl) generateRSAKey(keyLen int, ephemeral bool) (ski []byte, pubKey *rsa.PublicKey, err error) {
	if keyLen != 1024 && keyLen != 2048 && keyLen != 3072 && keyLen != 4096 {
		return nil, nil, errors.New("Invalid rsa key length, It must be 1024|2048|3072|4096")
	}
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	id := nextIDCtr()
	label := fmt.Sprintf("RSASignKey%s", id.Text(16))
	publicExponent := []byte{1, 0, 1}

	pubkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keyLen),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, publicExponent),
		//pkcs11.NewAttribute(pkcs11.CKA_ID, label),
	}

	prvkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
		//pkcs11.NewAttribute(pkcs11.CKR_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}

	pub, prv, err := p11lib.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubkey_t, prvkey_t)

	if err != nil {
		return nil, nil, fmt.Errorf("P11: keypair generate failed [%s]\n", err)
	}

	n, e, err := csp.pubParams(p11lib, session, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("Get RSA key from publickey err [%s]", err)
	}
	tN := new(big.Int).SetBytes(n)
	tE := int(new(big.Int).SetBytes(e).Int64())
	pubKey = &rsa.PublicKey{tN, tE}
	//set ski, refers to rsaPrivateKey SKI()
	raw, _ := asn1.Marshal(rsaPublicKeyASN{N: tN, E: tE})
	hash := sha256.New()
	hash.Write(raw)
	ski = hash.Sum(nil)
	setski_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
	}

	err = p11lib.SetAttributeValue(session, pub, setski_t)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: set RSA ski[public] failed [%s]\n", err)
	}

	err = p11lib.SetAttributeValue(session, prv, setski_t)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: set RSA ski[private] failed [%s]\n", err)
	}
	/*
		if logger.IsEnabledFor(logging.DEBUG) {
			listAttrs(p11lib, session, prv)
			listAttrs(p11lib, session, pub)
		}
	*/
	return ski, pubKey, nil
}

func (csp *impl) signP11RSA(ski []byte, msg []byte) (sig []byte, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	privateKey, err := findKeyPairFromSKI(p11lib, session, ski, isPrivateKey)
	fmt.Println("privateKey=", privateKey)
	if err != nil {
		return nil, fmt.Errorf("Private key not found [%s]\n", err)
	}

	err = p11lib.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, *privateKey)
	if err != nil {
		return nil, fmt.Errorf("Sign-initialize  failed [%s]\n", err)
	}

	sig, err = p11lib.Sign(session, msg)
	if err != nil {
		return nil, fmt.Errorf("P11: sign failed [%s]\n", err)
	}

	return sig, nil
}

func (csp *impl) verifyP11RSA(ski, msg, sig []byte) (valid bool, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	logger.Debugf("Verify RSA\n")

	publicKey, err := findKeyPairFromSKI(p11lib, session, ski, isPublicKey)
	if err != nil {
		return false, fmt.Errorf("Public key not found [%s]\n", err)
	}

	err = p11lib.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)},
		*publicKey)
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

func (csp *impl) importRSAKey(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey, ephemeral bool, isPrivate bool) (ski []byte, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	id := nextIDCtr()
	label := fmt.Sprintf("RSASignKey%s", id.Text(16))
	//label := fmt.Sprintf("RSASignKey%s", "49")
	raw, _ := asn1.Marshal(rsaPublicKeyASN{
		N: pubKey.N,
		E: pubKey.E,
	})
	hash := sha256.New()
	hash.Write(raw)
	ski = hash.Sum(nil)

	var keyTemplate []*pkcs11.Attribute
	if isPrivate == isPublicKey { //rsa public key
		publicExponent := []byte{1, 0, 1}
		keyLen := len(pubKey.N.Bytes()) * 8 //bits
		pModules := pubKey.N.Bytes()

		keyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			/*key data*/
			//refer to ~/warm3snow/bccsp_pkcs11/demo/RSATest.c #Line:169
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keyLen),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, pModules),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, publicExponent),
		}

	} else { //rsa private key
		ski, err := csp.importRSAKey(nil, &privKey.PublicKey, ephemeral, isPublicKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to import RSA private key [%s]\n", err)
		}
		pub := privKey.PublicKey
		n := pub.N                                   //big.Int
		e := pub.E                                   //int
		d := privKey.D                               //big.Int
		p, q := privKey.Primes[0], privKey.Primes[1] //big.Int
		one := new(big.Int).SetInt64(1)
		pSub1, qSub1 := p.Sub(q, one), q.Sub(q, one)

		pModules := n.Bytes()
		keyLen := len(pModules) * 8
		publicExponent := big.NewInt(int64(e)).Bytes()
		privateExponent := d.Bytes()
		prime1, prime2 := p.Bytes(), q.Bytes()
		exp1, exp2 := new(big.Int).Mod(d, pSub1).Bytes(), new(big.Int).Mod(d, qSub1).Bytes()
		coef := privKey.Precomputed.Qinv.Bytes()

		keyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			/*key data*/
			//refer to ~/warm3snow/bccsp_pkcs11/demo/RSATest.c #Line:169
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keyLen),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, pModules),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, publicExponent),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, privateExponent),
			pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, prime1),
			pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, prime2),
			pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, exp1),
			pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, exp2),
			pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, coef),
		}

	}

	keyHandle, err := p11lib.CreateObject(session, keyTemplate)
	if err != nil {
		return nil, fmt.Errorf("P11: keypair generate failed [%s]\n", err)
	}
	_ = keyHandle

	/*
		if logger.IsEnabledFor(logging.DEBUG) {
			listAttrs(p11lib, session, prv)
			listAttrs(p11lib, session, pub)
		}
	*/
	return ski, nil
}
