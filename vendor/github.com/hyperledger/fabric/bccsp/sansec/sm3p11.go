package sansec

import (
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/warm3snow/pkcs11"
)

const (
	nMaxDataLen = 1024 * 28
)

func (csp *impl) hashSM3(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	mech_t := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_SM3_HASH, nil),
	}
	err = p11lib.DigestInit(session, mech_t)
	if err != nil {
		return nil, fmt.Errorf("Failed init SM3, err [%s]", err)
	}
	ncount := len(msg) / nMaxDataLen
	for i := 0; i < ncount; i++ {
		err := p11lib.DigestUpdate(session, msg[i*nMaxDataLen:(i+1)*nMaxDataLen])
		if err != nil {
			return nil, fmt.Errorf("Failed update SM3 data, err [%s]", err)
		}
	}
	if len(msg)%nMaxDataLen != 0 {
		err := p11lib.DigestUpdate(session, msg[ncount*nMaxDataLen:])
		if err != nil {
			return nil, fmt.Errorf("Failed update SM3 data, err [%s]", err)
		}
	}
	digest, err = p11lib.DigestFinal(session)
	if err != nil {
		return nil, fmt.Errorf("SM3 final err [%s]", err)
	}
	return digest, nil
}
