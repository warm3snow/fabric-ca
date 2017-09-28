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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/warm3snow/pkcs11"
	"github.com/warm3snow/gmsm/sm2"
	"golang.org/x/crypto/sha3"
)

var (
	logger           = flogging.MustGetLogger("sansec_p11")
	sessionCacheSize = 10
)

// New returns a new instance of the sansec-based BCCSP
// set at the passed security level, hash family and KeyStore.
func New(opts SansecP11Opts, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(opts.SecLevel, opts.HashFamily)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing configuration [%s]", err)
	}

	swCSP, err := sw.New(opts.SecLevel, opts.HashFamily, keyStore)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing fallback SW BCCSP [%s]", err)
	}

	// Check KeyStore
	if keyStore == nil {
		return nil, errors.New("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}

	lib := opts.Library
	pin := opts.Pin
	label := opts.Label
	ctx, slot, session, err := loadLib(lib, pin, label)
	if err != nil {
		return nil, fmt.Errorf("Failed initializing PKCS11 library %s %s [%s]", lib, label, err)
	}
	sessions := make(chan pkcs11.SessionHandle, sessionCacheSize)
	csp := &impl{swCSP, conf, keyStore, ctx, sessions, slot, lib, opts.Sensitive, opts.SoftVerify}
	csp.returnSession(*session)

	return csp, nil
}

// SoftwareBasedBCCSP is the software-based implementation of the BCCSP.
type impl struct {
	bccsp.BCCSP

	conf *config
	ks   bccsp.KeyStore

	ctx      *pkcs11.Ctx
	sessions chan pkcs11.SessionHandle
	slot     uint

	lib          string
	noPrivImport bool
	SoftVerify   bool
}

// KeyGen generates a key using opts.
func (csp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	pkcs11Stored := false

	// Parse algorithm
	switch opts.(type) {
	case *bccsp.SM2KeyGenOpts:
		ski, pub, err := csp.generateSM2Key(opts.Ephemeral())
		if err != nil {
			return nil, fmt.Errorf("Failed generating SM2 key [%s]", err)
		}
		k = &sm2PrivateKey{ski, sm2PublicKey{ski, pub}}
		pkcs11Stored = true

	case *bccsp.ECDSAKeyGenOpts:
		ski, pub, err := csp.generateECKey(csp.conf.ellipticCurve, opts.Ephemeral())
		if err != nil {
			return nil, fmt.Errorf("Failed generating ECDSA key [%s]", err)
		}
		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}
		pkcs11Stored = true

	case *bccsp.ECDSAP256KeyGenOpts:
		ski, pub, err := csp.generateECKey(oidNamedCurveP256, opts.Ephemeral())
		fmt.Println("\nski=", ski, "\npub=", pub)
		if err != nil {
			return nil, fmt.Errorf("Failed generating ECDSA P256 key [%s]", err)
		}

		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}
		pkcs11Stored = true

	case *bccsp.ECDSAP384KeyGenOpts:
		ski, pub, err := csp.generateECKey(oidNamedCurveP384, opts.Ephemeral())
		if err != nil {
			return nil, fmt.Errorf("Failed generating ECDSA P384 key [%s]", err)
		}

		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}
		pkcs11Stored = true

	case *bccsp.AESKeyGenOpts:
		lowLevelKey, err := csp.generateAESKey(csp.conf.aesBitLength)

		if err != nil {
			return nil, fmt.Errorf("Failed generating AES key [%s]", err)
		}

		k = &aesPrivateKey{lowLevelKey, false}

	case *bccsp.AES256KeyGenOpts:
		lowLevelKey, err := csp.generateAESKey(32)

		if err != nil {
			return nil, fmt.Errorf("Failed generating AES 256 key [%s]", err)
		}

		k = &aesPrivateKey{lowLevelKey, false}

	case *bccsp.AES192KeyGenOpts:
		lowLevelKey, err := csp.generateAESKey(24)

		if err != nil {
			return nil, fmt.Errorf("Failed generating AES 192 key [%s]", err)
		}

		k = &aesPrivateKey{lowLevelKey, false}

	case *bccsp.AES128KeyGenOpts:
		lowLevelKey, err := csp.generateAESKey(16)

		if err != nil {
			return nil, fmt.Errorf("Failed generating AES 128 key [%s]", err)
		}

		k = &aesPrivateKey{lowLevelKey, false}

	case *bccsp.SM4KeyGenOpts:
		key, err := csp.generateSM4Key(16)
		if err != nil {
			return nil, fmt.Errorf("Failed generating SM4 key [%s]", err)
		}
		k = &sm4PrivateKey{key, false}

	case *bccsp.RSAKeyGenOpts:
		ski, pubKey, err := csp.generateRSAKey(csp.conf.rsaBitLength, opts.Ephemeral())

		if err != nil {
			return nil, fmt.Errorf("Failed generating RSA key [%s]", err)
		}

		k = &rsaPrivateKey{ski, rsaPublicKey{ski, pubKey}}
		pkcs11Stored = true

	case *bccsp.RSA1024KeyGenOpts:
		ski, pubKey, err := csp.generateRSAKey(1024, opts.Ephemeral())

		if err != nil {
			return nil, fmt.Errorf("Failed generating RSA 1024 key [%s]", err)
		}

		k = &rsaPrivateKey{ski, rsaPublicKey{ski, pubKey}}
		pkcs11Stored = true

	case *bccsp.RSA2048KeyGenOpts:
		ski, pubKey, err := csp.generateRSAKey(2048, opts.Ephemeral())

		if err != nil {
			return nil, fmt.Errorf("Failed generating RSA 2048 key [%s]", err)
		}
		k = &rsaPrivateKey{ski, rsaPublicKey{ski, pubKey}}
		pkcs11Stored = true

	case *bccsp.RSA3072KeyGenOpts:
		ski, pubKey, err := csp.generateRSAKey(3072, opts.Ephemeral())

		if err != nil {
			return nil, fmt.Errorf("Failed generating RSA 3072 key [%s]", err)
		}

		k = &rsaPrivateKey{ski, rsaPublicKey{ski, pubKey}}
		pkcs11Stored = true

	case *bccsp.RSA4096KeyGenOpts:
		ski, pubKey, err := csp.generateRSAKey(4096, opts.Ephemeral())

		if err != nil {
			return nil, fmt.Errorf("Failed generating RSA 4096 key [%s]", err)
		}

		k = &rsaPrivateKey{ski, rsaPublicKey{ski, pubKey}}
		pkcs11Stored = true

	default:
		return nil, fmt.Errorf("Unrecognized KeyGenOpts provided [%s]", opts.Algorithm())
	}

	// If the key is not Ephemeral, store it. SM2/EC/RSA Keys now in HSM, no need to store
	if !pkcs11Stored && !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, fmt.Errorf("Failed storing key [%s]. [%s]", opts.Algorithm(), err)
		}
	}

	return k, nil
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	// Derive key
	switch k.(type) {
	case *sm2PublicKey:
		if opts == nil {
			return nil, errors.New("Invalid Opts parameter. It must not be nil")
		}

		pubKey := k.(*sm2PublicKey)

		switch opts.(type) {
		case *bccsp.SM2ReRandKeyOpts:
			pub := pubKey.pub
			if pub == nil {
				return nil, errors.New("Public base key cannot be nil")
			}
			reRandOpts := opts.(*bccsp.SM2ReRandKeyOpts)
			tempSK := &sm2.PublicKey{
				Curve: pub.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			}
			var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
			var one = new(big.Int).SetInt64(1)
			n := new(big.Int).Sub(pub.Params().N, one)
			k.Mod(k, n)
			k.Add(k, one)

			tempX, tempY := pub.ScalarBaseMult(k.Bytes())
			tempSK.X, tempSK.Y = tempSK.Add(
				pub.X, pub.Y,
				tempX, tempY,
			)
			//verify if tmp public key is a valid point on curve
			isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
			if !isOn {
				return nil, errors.New("Failed temp Public Key IsOnCurve check.")
			}

			ecPt := elliptic.Marshal(tempSK.Curve, tempSK.X, tempSK.Y)
			ski, err := csp.importSM2Key(nil, ecPt[1:], opts.Ephemeral(), isPublicKey)
			if err != nil {
				return nil, fmt.Errorf("Failed importing SM2 Public Key [%s]", err)
			}
			reRandomizedKey := &sm2PublicKey{ski, tempSK}
			return reRandomizedKey, nil

		default:
			return nil, fmt.Errorf("Unrecognized KeyDerivOpts provided [%s]", opts.Algorithm())
			//sm2PrivateKey should be generated by User, the SKI is from the importSM2Key step
		}

	case *sm2PrivateKey:
		//Validate opts
		if opts == nil {
			return nil, errors.New("Invalid Opts parameter. It must not be nil")
		}

		smK := k.(*sm2PrivateKey)
		switch opts.(type) {
		//Re-rand
		case *bccsp.SM2ReRandKeyOpts:
			reRandOpts := opts.(*bccsp.SM2ReRandKeyOpts)
			pub := smK.pub.pub
			if pub == nil {
				return nil, errors.New("Public base key cannot be nil.")
			}
			//d always be zero, because the imported private key cannot be exported. Should use P11 derivekey. FIXME
			//This part of codes will be changed in the fulture.
			d := csp.getSecretValue(smK.ski)
			if d == nil {
				return nil, errors.New("Couldn't get SM2 private Key")
			}
			bigD := new(big.Int).SetBytes(d)

			tempSK := &sm2.PrivateKey{
				PublicKey: sm2.PublicKey{
					Curve: pub.Curve,
					X:     new(big.Int),
					Y:     new(big.Int),
				},
				D: new(big.Int),
			}
			var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
			var one = new(big.Int).SetInt64(1)
			n := new(big.Int).Sub(pub.Params().N, one)
			k.Mod(k, n)
			k.Add(k, one)

			tempSK.D.Add(bigD, k)
			tempSK.D.Mod(tempSK.D, pub.Params().N)

			//compute tmp public key
			tempSK.PublicKey.X, tempSK.PublicKey.Y = pub.ScalarBaseMult(tempSK.D.Bytes())
			//verify point on curve
			isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
			if !isOn {
				return nil, errors.New("Failed checking tmp public key IsOnCurve")
			}

			ecPt := elliptic.Marshal(tempSK.Curve, tempSK.X, tempSK.Y)

			ski, err := csp.importSM2Key(tempSK.D.Bytes(), ecPt[1:], opts.Ephemeral(), isPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("Failed importing SM2 Private Key [%s]", err)
			}
			reRandomizedKey := &sm2PrivateKey{ski, sm2PublicKey{ski, &tempSK.PublicKey}}

			return reRandomizedKey, nil
		default:
			return nil, fmt.Errorf("Unrecognized KeyDerivOpts provided [%s]", opts.Algorithm())
		}

	case *ecdsaPublicKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid Opts parameter. It must not be nil.")
		}

		ecdsaK := k.(*ecdsaPublicKey)

		switch opts.(type) {

		// Re-randomized an ECDSA public key
		case *bccsp.ECDSAReRandKeyOpts:
			pubKey := ecdsaK.pub
			reRandOpts := opts.(*bccsp.ECDSAReRandKeyOpts)
			tempSK := &ecdsa.PublicKey{
				Curve: pubKey.Curve,
				X:     new(big.Int),
				Y:     new(big.Int),
			}

			var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
			var one = new(big.Int).SetInt64(1)
			n := new(big.Int).Sub(pubKey.Params().N, one)
			k.Mod(k, n)
			k.Add(k, one)

			// Compute temporary public key
			tempX, tempY := pubKey.ScalarBaseMult(k.Bytes())
			tempSK.X, tempSK.Y = tempSK.Add(
				pubKey.X, pubKey.Y,
				tempX, tempY,
			)

			// Verify temporary public key is a valid point on the reference curve
			isOn := tempSK.Curve.IsOnCurve(tempSK.X, tempSK.Y)
			if !isOn {
				return nil, errors.New("Failed temporary public key IsOnCurve check.")
			}

			ecPt := elliptic.Marshal(tempSK.Curve, tempSK.X, tempSK.Y)
			oid, ok := oidFromNamedCurve(tempSK.Curve)
			if !ok {
				return nil, errors.New("Do not know OID for this Curve.")
			}

			ski, err := csp.importECKey(oid, nil, ecPt, opts.Ephemeral(), isPublicKey)
			if err != nil {
				return nil, fmt.Errorf("Failed getting importing EC Public Key [%s]", err)
			}
			reRandomizedKey := &ecdsaPublicKey{ski, tempSK}

			return reRandomizedKey, nil

		default:
			return nil, fmt.Errorf("Unrecognized KeyDerivOpts provided [%s]", opts.Algorithm())

		}
	case *ecdsaPrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid Opts parameter. It must not be nil.")
		}

		ecdsaK := k.(*ecdsaPrivateKey)

		switch opts.(type) {

		// Re-randomized an ECDSA private key
		case *bccsp.ECDSAReRandKeyOpts:
			reRandOpts := opts.(*bccsp.ECDSAReRandKeyOpts)
			pubKey := ecdsaK.pub.pub
			secret := csp.getSecretValue(ecdsaK.ski)
			if secret == nil {
				return nil, errors.New("Could not obtain EC Private Key")
			}
			bigSecret := new(big.Int).SetBytes(secret)

			tempSK := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: pubKey.Curve,
					X:     new(big.Int),
					Y:     new(big.Int),
				},
				D: new(big.Int),
			}

			var k = new(big.Int).SetBytes(reRandOpts.ExpansionValue())
			var one = new(big.Int).SetInt64(1)
			n := new(big.Int).Sub(pubKey.Params().N, one)
			k.Mod(k, n)
			k.Add(k, one)

			tempSK.D.Add(bigSecret, k)
			tempSK.D.Mod(tempSK.D, pubKey.Params().N)

			// Compute temporary public key
			tempSK.PublicKey.X, tempSK.PublicKey.Y = pubKey.ScalarBaseMult(tempSK.D.Bytes())

			// Verify temporary public key is a valid point on the reference curve
			isOn := tempSK.Curve.IsOnCurve(tempSK.PublicKey.X, tempSK.PublicKey.Y)
			if !isOn {
				return nil, errors.New("Failed temporary public key IsOnCurve check.")
			}

			ecPt := elliptic.Marshal(tempSK.Curve, tempSK.X, tempSK.Y)
			oid, ok := oidFromNamedCurve(tempSK.Curve)
			if !ok {
				return nil, errors.New("Do not know OID for this Curve.")
			}

			ski, err := csp.importECKey(oid, tempSK.D.Bytes(), ecPt, opts.Ephemeral(), isPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("Failed getting importing EC Public Key [%s]", err)
			}
			reRandomizedKey := &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, &tempSK.PublicKey}}

			return reRandomizedKey, nil

		default:
			return nil, fmt.Errorf("Unrecognized KeyDerivOpts provided [%s]", opts.Algorithm())

		}
	case *aesPrivateKey:
		// Validate opts
		if opts == nil {
			return nil, errors.New("Invalid Opts parameter. It must not be nil.")
		}

		aesK := k.(*aesPrivateKey)

		switch opts.(type) {
		case *bccsp.HMACTruncated256AESDeriveKeyOpts:
			hmacOpts := opts.(*bccsp.HMACTruncated256AESDeriveKeyOpts)

			mac := hmac.New(csp.conf.hashFunction, aesK.privKey)
			mac.Write(hmacOpts.Argument())
			hmacedKey := &aesPrivateKey{mac.Sum(nil)[:csp.conf.aesBitLength], false}

			// If the key is not Ephemeral, store it.
			if !opts.Ephemeral() {
				// Store the key
				err = csp.ks.StoreKey(hmacedKey)
				if err != nil {
					return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
				}
			}

			return hmacedKey, nil

		case *bccsp.HMACDeriveKeyOpts:

			hmacOpts := opts.(*bccsp.HMACDeriveKeyOpts)

			mac := hmac.New(csp.conf.hashFunction, aesK.privKey)
			mac.Write(hmacOpts.Argument())
			hmacedKey := &aesPrivateKey{mac.Sum(nil), true}

			// If the key is not Ephemeral, store it.
			if !opts.Ephemeral() {
				// Store the key
				err = csp.ks.StoreKey(hmacedKey)
				if err != nil {
					return nil, fmt.Errorf("Failed storing ECDSA key [%s]", err)
				}
			}

			return hmacedKey, nil

		default:
			return nil, fmt.Errorf("Unrecognized KeyDerivOpts provided [%s]", opts.Algorithm())

		}

	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. Cannot be nil")
	}

	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	switch opts.(type) {

	case *bccsp.AES256ImportKeyOpts:
		aesRaw, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[AES256ImportKeyOpts] Invalid raw material. Expected byte array.")
		}

		if len(aesRaw) != 32 {
			return nil, fmt.Errorf("[AES256ImportKeyOpts] Invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
		}

		aesK := &aesPrivateKey{utils.Clone(aesRaw), false}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.StoreKey(aesK)
			if err != nil {
				return nil, fmt.Errorf("Failed storing AES key [%s]", err)
			}
		}

		return aesK, nil

	case *bccsp.HMACImportKeyOpts:
		aesRaw, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[HMACImportKeyOpts] Invalid raw material. Expected byte array.")
		}

		if len(aesRaw) == 0 {
			return nil, errors.New("[HMACImportKeyOpts] Invalid raw. It must not be nil.")
		}

		aesK := &aesPrivateKey{utils.Clone(aesRaw), false}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.StoreKey(aesK)
			if err != nil {
				return nil, fmt.Errorf("Failed storing AES key [%s]", err)
			}
		}

		return aesK, nil

	case *bccsp.ECDSAPKIXPublicKeyImportOpts:
		der, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[ECDSAPKIXPublicKeyImportOpts] Invalid raw material. Expected byte array.")
		}

		if len(der) == 0 {
			return nil, errors.New("[ECDSAPKIXPublicKeyImportOpts] Invalid raw. It must not be nil.")
		}

		lowLevelKey, err := utils.DERToPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
		}

		ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
		}

		ecPt := elliptic.Marshal(ecdsaPK.Curve, ecdsaPK.X, ecdsaPK.Y)
		oid, ok := oidFromNamedCurve(ecdsaPK.Curve)
		if !ok {
			return nil, errors.New("Do not know OID for this Curve.")
		}

		ski, err := csp.importECKey(oid, nil, ecPt, opts.Ephemeral(), isPublicKey)
		if err != nil {
			return nil, fmt.Errorf("Failed getting importing EC Public Key [%s]", err)
		}

		k = &ecdsaPublicKey{ski, ecdsaPK}
		return k, nil

	case *bccsp.ECDSAPrivateKeyImportOpts:
		der, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
		}

		if len(der) == 0 {
			return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
		}

		lowLevelKey, err := utils.DERToPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
		}

		ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
		}

		ecPt := elliptic.Marshal(ecdsaSK.Curve, ecdsaSK.X, ecdsaSK.Y)
		oid, ok := oidFromNamedCurve(ecdsaSK.Curve)
		if !ok {
			return nil, errors.New("Do not know OID for this Curve.")
		}

		ski, err := csp.importECKey(oid, ecdsaSK.D.Bytes(), ecPt, opts.Ephemeral(), isPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("Failed getting importing EC Private Key [%s]", err)
		}

		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, &ecdsaSK.PublicKey}}
		return k, nil

	case *bccsp.ECDSAGoPublicKeyImportOpts:
		lowLevelKey, ok := raw.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("[ECDSAGoPublicKeyImportOpts] Invalid raw material. Expected *ecdsa.PublicKey.")
		}

		ecPt := elliptic.Marshal(lowLevelKey.Curve, lowLevelKey.X, lowLevelKey.Y)
		oid, ok := oidFromNamedCurve(lowLevelKey.Curve)
		if !ok {
			return nil, errors.New("Do not know OID for this Curve.")
		}

		ski, err := csp.importECKey(oid, nil, ecPt, opts.Ephemeral(), isPublicKey)
		if err != nil {
			return nil, fmt.Errorf("Failed getting importing EC Public Key [%s]", err)
		}

		k = &ecdsaPublicKey{ski, lowLevelKey}
		return k, nil

		//sm2 key import
	case *bccsp.SM2PKIXPublicKeyImportOpts:
		//return nil, errors.New("[SM2PKIXPublicKeyImportOpts] No Need to import public key, set SoftVerify")
		der, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[SM2PKIXPublicKeyImportOpts] Invalid raw material. Expected byte arrary.")
		}
		if len(der) == 0 {
			return nil, errors.New("[SM2PKIXPublicKeyImportOpts] Invalid raw. It must not be nil.")
		}
		//lowLevelKey, err := sm2.ReadPublicKeyFromMem(der, []byte("pwd"))
		smPK, err := sm2.ParseSm2PublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
		}

		//soft ecPt has a prefix 0x04
		ecPt := elliptic.Marshal(smPK.Curve, smPK.X, smPK.Y)
		var ski []byte
		//don't support public SM2 key import if noPrivImport
		if csp.noPrivImport {
			hash := sha256.Sum256(ecPt[1:])
			ski = hash[:]
		} else {
			if !csp.SoftVerify {
				logger.Debugf("Don't support public SM2 key import. So verify with this PublicKey will fail unless it's already in p11 store.\n" +
					"Enable 'SoftVerify' in p11 options")
			}
			ski, err = csp.importSM2Key(nil, ecPt[1:], opts.Ephemeral(), isPublicKey)
			if err != nil {
				return nil, fmt.Errorf("Failed importing SM2 public key [%s]", err)
			}
		}

		k = &sm2PublicKey{ski, smPK}
		return k, nil

	case *bccsp.SM2PrivateKeyImportOpts:
		if csp.noPrivImport {
			return nil, errors.New("[SM2PrivateKeyImportOpts] P11 options 'sensitivekeys' is set to true. Cannot import.")
		}

		der, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("[SM2PKIXPrivateKeyImportOpts] Invalid raw material. Expected byte arrary.")
		}
		if len(der) == 0 {
			return nil, errors.New("[SM2PKIXPublicKeyImportOpts] Invalid raw. It must not be nil.")
		}

		//ReadPrivateKeyFromMem should be provided a pwd, default nil, how to supply a pwd? FIXME
		//smSK, err := sm2.ReadPrivateKeyFromMem(der, nil)
		//smSK, err := sm2.ParseSm2PrivateKey(der)
		//smSK, err := sm2.ParsePKCS8PrivateKey(der)
		key, err := utils.DERToPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("Failed converting PKIX to SM2 private key [%s]", err)
		}

		smSK := key.(*sm2.PrivateKey)
		ecPt := elliptic.Marshal(smSK.Curve, smSK.X, smSK.Y)
		ski, err := csp.importSM2Key(smSK.D.Bytes(), ecPt[1:], opts.Ephemeral(), isPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("Failed importing SM2 private key [%s]", err)
		}

		k = &sm2PrivateKey{ski, sm2PublicKey{ski, &smSK.PublicKey}}
		return k, nil

	case *bccsp.SM2GoPublicKeyImportOpts:
		//return nil, errors.New("[SM2PKIXPublicKeyImportOpts] No Need to import public key, set SoftVerify")
		lowLevelKey, ok := raw.(*sm2.PublicKey)
		if !ok {
			return nil, errors.New("[SM2GoPublicKeyImportOpts] Invalid raw material. Expected byte array")
		}
		ecPt := elliptic.Marshal(lowLevelKey.Curve, lowLevelKey.X, lowLevelKey.Y)

		var ski []byte
		if csp.noPrivImport {
			hash := sha256.Sum256(ecPt)
			ski = hash[:]
		} else {
			if !csp.SoftVerify {
				logger.Debugf("softwareverify warning~~")
			}
			ski, err = csp.importSM2Key(nil, ecPt[1:], opts.Ephemeral(), isPublicKey)
			if err != nil {
				return nil, fmt.Errorf("Failed importing SM2 Public Key [%s]", err)
			}
		}

		k = &sm2PublicKey{ski, lowLevelKey}
		return k, nil

	case *bccsp.RSAGoPublicKeyImportOpts:
		lowLevelKey, ok := raw.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("[RSAGoPublicKeyImportOpts] Invalid raw material. Expected *rsa.PublicKey.")
		}

		ski, err := csp.importRSAKey(nil, lowLevelKey, opts.Ephemeral(), isPublicKey)
		if err != nil {
			return nil, fmt.Errorf("Failed import rsaPublicKey, err[%s]", err)
		}
		k = &rsaPublicKey{ski, lowLevelKey}

		// If the key is not Ephemeral, store it.
		if !opts.Ephemeral() {
			// Store the key
			err = csp.ks.StoreKey(k)
			if err != nil {
				return nil, fmt.Errorf("Failed storing RSA publi key [%s]", err)
			}
		}

		return k, nil

	case *bccsp.X509PublicKeyImportOpts:
		x509Cert, ok := raw.(*x509.Certificate)
		if !ok {
			return nil, errors.New("[X509PublicKeyImportOpts] Invalid raw material. Expected *x509.Certificate.")
		}

		pk := x509Cert.PublicKey

		switch pk.(type) {
		case *ecdsa.PublicKey:
			return csp.KeyImport(pk, &bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
		case *rsa.PublicKey:
			return csp.KeyImport(pk, &bccsp.RSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
		case *sm2.PublicKey:
			return csp.KeyImport(pk, &bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
		default:
			return nil, errors.New("Certificate public key type not recognized. Supported keys: [ECDSA, RSA]")
		}

	default:
		return nil, errors.New("Import Key Options not recognized")
	}
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
//Args:
//		ski = prefix + SKI
//RSA,ECDSA,SM2
func (csp *impl) GetKey(ski []byte) (k bccsp.Key, err error) {
	skistr := string(ski)
	if strings.HasPrefix(skistr, "ECDSA") {
		ski = ski[5:]
		pubKey, isPriv, err := csp.getECKey(ski)
		if err == nil {
			if isPriv {
				return &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pubKey}}, nil
			} else {
				return &ecdsaPublicKey{ski, pubKey}, nil
			}
		}
	} else if strings.HasPrefix(skistr, "SM2") {
		ski = ski[3:]
		pub, isPriv, err := csp.getSM2Key(ski)
		if err == nil {
			if isPriv {
				return &sm2PrivateKey{ski, sm2PublicKey{ski, pub}}, nil
			} else {
				return &sm2PublicKey{ski, pub}, nil
			}
		}
	} else if strings.HasPrefix(skistr, "RSA") {
		ski = ski[3:]
		pubKey, isPriv, err := csp.getRSAKey(ski)
		if err == nil {
			if isPriv {
				return &rsaPrivateKey{ski, rsaPublicKey{ski, pubKey}}, nil
			} else {
				return &rsaPublicKey{ski, pubKey}, nil
			}
		}
	}
	return csp.ks.GetKey(ski)
}

// Hash hashes messages msg using options opts.
func (csp *impl) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	var h hash.Hash
	if opts == nil {
		h = csp.conf.hashFunction()
	} else {
		switch opts.(type) {
		case *bccsp.SHAOpts:
			h = csp.conf.hashFunction()
		case *bccsp.SHA256Opts:
			h = sha256.New()
		case *bccsp.SHA384Opts:
			h = sha512.New384()
		case *bccsp.SHA3_256Opts:
			h = sha3.New256()
		case *bccsp.SHA3_384Opts:
			h = sha3.New384()
		case *bccsp.SM3Opts:
			return csp.hashSM3(msg, opts)
		default:
			return nil, fmt.Errorf("Algorithm not recognized [%s]", opts.Algorithm())
		}
	}

	h.Write(msg)
	return h.Sum(nil), nil
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (csp *impl) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	if opts == nil {
		return csp.conf.hashFunction(), nil
	}

	switch opts.(type) {
	case *bccsp.SHAOpts:
		return csp.conf.hashFunction(), nil
	case *bccsp.SHA256Opts:
		return sha256.New(), nil
	case *bccsp.SHA384Opts:
		return sha512.New384(), nil
	case *bccsp.SHA3_256Opts:
		return sha3.New256(), nil
	case *bccsp.SHA3_384Opts:
		return sha3.New384(), nil
	case *bccsp.SM3Opts:
		return nil, errors.New("Usage: bccsp.Hash(msg, &bccsp.SM3Opts{})")
	default:
		return nil, fmt.Errorf("Algorithm not recognized [%s]", opts.Algorithm())
	}
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	// Check key type
	switch k.(type) {
	case *sm2PrivateKey:
		return csp.signSM2(*k.(*sm2PrivateKey), digest, opts)
	case *ecdsaPrivateKey:
		return csp.signECDSA(*k.(*ecdsaPrivateKey), digest, opts)
	case *rsaPrivateKey:
		return csp.signRSA(*k.(*rsaPrivateKey), digest, opts)
	default:
		return csp.BCCSP.Sign(k, digest, opts)
	}
}

// Verify verifies signature against key k and digest
func (csp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty.")
	}

	// Check key type
	switch k.(type) {
	case *sm2PrivateKey:
		return csp.verifySM2(k.(*sm2PrivateKey).pub, signature, digest, opts)
	case *sm2PublicKey:
		return csp.verifySM2(*k.(*sm2PublicKey), signature, digest, opts)
	case *ecdsaPrivateKey:
		return csp.verifyECDSA(k.(*ecdsaPrivateKey).pub, signature, digest, opts)
	case *ecdsaPublicKey:
		return csp.verifyECDSA(*k.(*ecdsaPublicKey), signature, digest, opts)
	case *rsaPrivateKey:
		return csp.verifyRSA(k.(*rsaPrivateKey).pub, signature, digest, opts)
	case *rsaPublicKey:
		return csp.verifyRSA(*k.(*rsaPublicKey), signature, digest, opts)
	default:
		return false, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	// Check key type
	switch k.(type) {
	case *sm4PrivateKey:
		// check for mode
		switch opts.(type) {
		case *bccsp.SM4CBCPKCS7ModeOpts, bccsp.SM4CBCPKCS7ModeOpts:
			// SM4 in CBC mode with PKCS7 padding
			return csp.SM4CBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
		default:
			return nil, fmt.Errorf("Mode not recognized [%s]", opts)
		}

	case *aesPrivateKey:
		// check for mode
		switch opts.(type) {
		case *bccsp.AESCBCPKCS7ModeOpts, bccsp.AESCBCPKCS7ModeOpts:
			// AES in CBC mode with PKCS7 padding
			return csp.AESCBCPKCS7Encrypt(k.(*aesPrivateKey).privKey, plaintext)
		default:
			return nil, fmt.Errorf("Mode not recognized [%s]", opts)
		}
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	// Check key type
	switch k.(type) {
	case *sm4PrivateKey:
		// check for mode
		switch opts.(type) {
		case *bccsp.SM4CBCPKCS7ModeOpts, bccsp.SM4CBCPKCS7ModeOpts:
			// AES in CBC mode with PKCS7 padding
			return csp.SM4CBCPKCS7Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
		default:
			return nil, fmt.Errorf("Mode not recognized [%s]", opts)
		}

	case *aesPrivateKey:
		// check for mode
		switch opts.(type) {
		case *bccsp.AESCBCPKCS7ModeOpts, bccsp.AESCBCPKCS7ModeOpts:
			// AES in CBC mode with PKCS7 padding
			return csp.AESCBCPKCS7Decrypt(k.(*aesPrivateKey).privKey, ciphertext)
		default:
			return nil, fmt.Errorf("Mode not recognized [%s]", opts)
		}
	default:
		return nil, fmt.Errorf("Key type not recognized [%s]", k)
	}
}
