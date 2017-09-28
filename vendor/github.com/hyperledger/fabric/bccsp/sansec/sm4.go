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
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/warm3snow/pkcs11"
)

//sm4.BlockSize = 16

//generateSM4Key returns a p11 sm4 key
func (csp *impl) generateSM4Key(len int) ([]byte, error) {
	if len != 16 {
		return nil, errors.New("Invalid sm4 key length, should be [ 16 ]")
	}
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	sm4_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, len),
	}

	mech_t := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_IBM_SM4_KEY_GEN, nil),
	}

	hSecKey, err := p11lib.GenerateKey(session, mech_t, sm4_t)
	if err != nil {
		return nil, fmt.Errorf("SM4 Gen key err[%s]", err)
	}

	sm4Val_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attr, err := p11lib.GetAttributeValue(session, hSecKey, sm4Val_t)
	if err != nil {
		return nil, fmt.Errorf("Get sm4 key err[%s]", err)
	}
	for _, a := range attr {
		return a.Value, nil
	}
	return nil, errors.New("Gen key failed!")
}
func (csp *impl) sm4CBCEncrypt(key, s []byte) ([]byte, error) {
	if len(s)%BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	ciphertext := make([]byte, BlockSize+len(s))
	iv := ciphertext[:BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mech_t := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_IBM_SM4_CBC, iv),
	}
	sm4_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
	}
	hSecKey, err := p11lib.CreateObject(session, sm4_t)
	if err != nil {
		return nil, err
	}
	err = p11lib.EncryptInit(session, mech_t, hSecKey)
	if err != nil {
		return nil, err
	}
	d, err := p11lib.Encrypt(session, s)
	if err != nil {
		return nil, err
	}
	copy(ciphertext[BlockSize:], d)
	return ciphertext, nil
}
func (csp *impl) sm4CBCDecrypt(key, src []byte) ([]byte, error) {
	if len(src)%BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	iv := src[:BlockSize]
	src = src[BlockSize:]

	mech_t := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_IBM_SM4_CBC, iv),
	}
	sm4_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
	}
	hSecKey, err := p11lib.CreateObject(session, sm4_t)
	if err != nil {
		return nil, err
	}
	err = p11lib.DecryptInit(session, mech_t, hSecKey)
	if err != nil {
		return nil, err
	}
	d, err := p11lib.Decrypt(session, src)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// SM4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func (csp *impl) SM4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return csp.sm4CBCEncrypt(key, tmp)
}

// SM4CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func (csp *impl) SM4CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := csp.sm4CBCDecrypt(key, src)
	if err != nil {
		return nil, err
	}

	// Then remove padding
	original, err := pkcs7UnPadding(pt)
	if err != nil {
		return nil, err
	}

	return original, nil
}
