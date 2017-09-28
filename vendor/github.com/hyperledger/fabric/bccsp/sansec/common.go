package sansec

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/warm3snow/pkcs11"
)

func loadLib(lib, pin, label string) (*pkcs11.Ctx, uint, *pkcs11.SessionHandle, error) {
	var slot uint = 0
	logger.Debugf("Loading pkcs11 library [%s]\n", lib)
	if lib == "" {
		return nil, slot, nil, fmt.Errorf("No PKCS11 library default")
	}

	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, slot, nil, fmt.Errorf("Instantiate failed [%s]", lib)
	}

	ctx.Initialize()
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, slot, nil, fmt.Errorf("Could not get slot List [%s]", err)

	}
	found := false
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		logger.Debugf("Looking for %s, found label %s\n", label, info.Label)
		if label == info.Label {
			found = true
			slot = s
			break
		}
	}
	if !found {
		return nil, slot, nil, fmt.Errorf("Could not find token with label %s", label)
	}
	var session pkcs11.SessionHandle
	for i := 0; i < 10; i++ {
		session, err = ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			logger.Warningf("OpenSession failed, retrying [%s]\n", err)
		} else {
			break
		}
	}
	if err != nil {
		logger.Fatalf("OpenSession failed[%s]\n", err)
	}
	logger.Debugf("Created new pkcs11 session %+v on slot %d\n", session, slot)

	if pin == "" {
		return nil, slot, nil, fmt.Errorf("No PIN set\n")

	}
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, slot, nil, fmt.Errorf("Login failed [%s]\n", err)
		}
	}

	return ctx, slot, &session, nil
}

func (csp *impl) getSession() (session pkcs11.SessionHandle) {
	select {
	case session = <-csp.sessions:
		logger.Debugf("Reusing existing pkcs11 session %+v on slot %d\n", session, csp.slot)

	default:
		// create one (empty or completely in use)
		var s pkcs11.SessionHandle
		var err error = nil
		for i := 0; i < 10; i++ {
			s, err = csp.ctx.OpenSession(csp.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
			if err != nil {
				logger.Warningf("OpenSession failed, retrying [%s]\n", err)
			} else {
				break
			}
		}
		if err != nil {
			logger.Fatalf("OpenSession failed [%s]\n", err)

		}
		logger.Debugf("Created new pkcs11 session %+v on slot %d\n", s, csp.slot)
		session = s

	}
	return session

}

func (csp *impl) returnSession(session pkcs11.SessionHandle) {
	select {
	case csp.sessions <- session:
	default:
		csp.ctx.CloseSession(session)
	}
}

const (
	isPrivateKey = true
	isPublicKey  = false
)

func findKeyPairFromSKI(mod *pkcs11.Ctx, session pkcs11.SessionHandle, ski []byte, keyType bool) (*pkcs11.ObjectHandle, error) {
	ktype := pkcs11.CKO_PUBLIC_KEY
	if keyType == isPrivateKey {
		ktype = pkcs11.CKO_PRIVATE_KEY

	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ktype),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
	}
	if err := mod.FindObjectsInit(session, template); err != nil {
		return nil, err

	}

	// single session instance, assume one hit only
	objs, _, err := mod.FindObjects(session, 1)
	if err != nil {
		return nil, err

	}
	if err = mod.FindObjectsFinal(session); err != nil {
		return nil, err

	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("Key not found [%s]", hex.Dump(ski))

	}

	return &objs[0], nil

}

// Fairly straightforward EC-point query, other than opencryptoki
// mis-reporting length, including the 04 Tag of the field following
// the SPKI in EP11-returned MACed publickeys:
//
// SoftHSM reports extra two bytes before the uncrompressed point
// 0x04 || <Length*2+1>
//                 VV< Actual start of point
// 00000000  04 41 04 6c c8 57 32 13  02 12 6a 19 23 1d 5a 64  |.A.l.W2...j.#.Zd|
// 00000010  33 0c eb 75 4d e8 99 22  92 35 96 b2 39 58 14 1e  |3..uM..".5..9X..|
// 00000020  19 de ef 32 46 50 68 02  24 62 36 db ed b1 84 7b  |...2FPh.$b6....{|
// 00000030  93 d8 40 c3 d5 a6 b7 38  16 d2 35 0a 53 11 f9 51  |..@....8..5.S..Q|
// 00000040  fc a7 16                                          |...|

func ecPoint(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (ecpt, oid []byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	}

	attr, err := p11lib.GetAttributeValue(session, key, template)
	if err != nil {
		return nil, nil, fmt.Errorf("PKCS11: get(EC point) [%s]\n", err)

	}

	for _, a := range attr {
		if a.Type == pkcs11.CKA_EC_POINT {
			logger.Debugf("EC point: attr type %d/0x%x, len %d\n%s\n", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

			// workarounds, see above
			if (0 == (len(a.Value) % 2)) &&
				(byte(0x04) == a.Value[0]) &&
				(byte(0x04) == a.Value[len(a.Value)-1]) {
				logger.Debugf("Detected opencryptoki bug, trimming trailing 0x04")
				ecpt = a.Value[0 : len(a.Value)-1] // Trim trailing 0x04

			} else if byte(0x04) == a.Value[0] && byte(0x04) == a.Value[2] {
				logger.Debugf("Detected SoftHSM bug, trimming leading 0x04 0xXX")
				ecpt = a.Value[2:len(a.Value)]

			} else {
				ecpt = a.Value

			}

		} else if a.Type == pkcs11.CKA_EC_PARAMS {
			logger.Debugf("EC point: attr type %d/0x%x, len %d\n%s\n", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

			oid = a.Value
		}

	}
	if oid == nil || ecpt == nil {
		return nil, nil, fmt.Errorf("CKA_EC_POINT not found, perhaps not an EC Key?")

	}

	return ecpt, oid, nil
}

/*
func ecPoint(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (ecpt, oid []byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		// pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),

	}

	attr, err := p11lib.GetAttributeValue(session, key, template)
	if err != nil {
		return nil, nil, fmt.Errorf("PKCS11: get(EC point) [%s]\n", err)

	}

	for _, a := range attr {
		ecpt = a.Value

	}
	if ecpt == nil {
		return nil, nil, fmt.Errorf("CKA_EC_POINT not found, perhaps not an EC Key?")

	}
	fmt.Println("ecpt=", ecpt, "len(ecpt)=", len(ecpt))
	return ecpt, nil, nil

}
*/

func listAttrs(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, obj pkcs11.ObjectHandle) {
	var cktype, ckclass uint
	var ckaid, cklabel, privKey []byte

	if p11lib == nil {
		return

	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ckclass),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, cktype),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaid),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, cklabel),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, privKey),
	}

	// certain errors are tolerated, if value is missing
	attr, err := p11lib.GetAttributeValue(session, obj, template)
	if err != nil {
		logger.Warningf("P11: get(attrlist) [%s]\n", err)

	}

	for _, a := range attr {
		// Would be friendlier if the bindings provided a way convert Attribute hex to string
		logger.Debugf("ListAttr: type %d/0x%x, length %d\n%s", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

	}

}

/*
func (csp *impl) getECPoint(ski []byte) ([]byte, error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	key, err := findKeyPairFromSKI(p11lib, session, ski, isPublicKey)
	//fmt.Println("pub keyHandel=", key)
	if err != nil {
		return nil, fmt.Errorf("Public key not found [%s] for SKI [%s]", err, hex.EncodeToString(ski))
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	attr, err := p11lib.GetAttributeValue(session, *key, template)
	if err != nil {
		return nil, fmt.Errorf("PKCS11: get(EC point) [%s]\n", err)
	}

	for _, a := range attr {
		return a.Value, nil
	}
	return nil, errors.New("No publickey found")
}
*/

func (csp *impl) getSecretValue(ski []byte) []byte {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	keyHandle, err := findKeyPairFromSKI(p11lib, session, ski, isPrivateKey)

	var privKey []byte
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, privKey),
	}

	// certain errors are tolerated, if value is missing
	attr, err := p11lib.GetAttributeValue(session, *keyHandle, template)
	if err != nil {
		logger.Warningf("P11: get(attrlist) [%s]\n", err)
	}

	//fmt.Println("attr[0]=", attr[0])
	for _, a := range attr {
		// Would be friendlier if the bindings provided a way convert Attribute hex to string
		fmt.Printf("ListAttr: type 0x%x, length %d\n%s", a.Type, len(a.Value), hex.Dump(a.Value))
		return a.Value
	}
	logger.Warningf("No Key Value found!", err)

	return nil
}

var (
	bigone   = new(big.Int).SetInt64(1)
	id_ctr   = new(big.Int)
	id_mutex sync.Mutex
)

func nextIDCtr() *big.Int {
	id_mutex.Lock()
	id_ctr = new(big.Int).Add(id_ctr, bigone)
	id_mutex.Unlock()
	return id_ctr
}
