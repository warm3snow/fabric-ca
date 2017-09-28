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
	"crypto/x509"
	"errors"

	"github.com/hyperledger/fabric/bccsp"
)

const (
	SM2 x509.PublicKeyAlgorithm = 5
	p                           = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
	a                           = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
	b                           = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
	n                           = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
	Gx                          = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
	Gy                          = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
)

type sm2PrivateKey struct {
	ski []byte
	pub sm2PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2PrivateKey) Bytes() (raw []byte, err error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *sm2PrivateKey) SKI() (ski []byte) {
	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &k.pub, nil
}

type sm2PublicKey struct {
	ski  []byte
	ecpt []byte
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2PublicKey) Bytes() (raw []byte, err error) {
	if k.ecpt == nil {
		return nil, errors.New("Not a valid SM2 PublicKey")
	}
	return k.ecpt, nil
}

// SKI returns the subject key identifier of this key.
func (k *sm2PublicKey) SKI() (ski []byte) {
	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *sm2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

/*
func PointMult(in []byte) (out []byte) {
	k := new(big.Int).SetBytes(in)
	x := new(big.Int).SetString(Gx, 16)
	y := new(big.Int).SetString(Gy, 16)

}
*/
