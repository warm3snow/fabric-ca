package sansec

import (
	"fmt"
	"os"
	"strings"
)

func FindPKCS11Lib() (lib, pin, label string) {
	lib = os.Getenv("PKCS11_LIB")
	if lib == "" {
		possibilities := []string{
			"/usr/lib/libupkcs11.so",
			"/usr/lib/softhsm/libsofthsm2.so",
		}
		for _, path := range possibilities {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				lib = path
				break
			}
		}
		if strings.Contains(lib, "softhsm") {
			pin = "98765432"
			label = "ForFabric"
		} else {
			pin = "66666666"
			label = "Sansec HSM"
		}
	} else {
		pin = os.Getenv("PKCS11_PIN")
		label = os.Getenv("PKCS11_LABEL")
	}
	return lib, pin, label
}

func EqualIntArrs(a, b []int) bool {
	if len(a) != len(b) {
		return false
	} else {
		for i := 0; i < len(a); i++ {
			if a[i] != b[i] {
				return false
			}
		}
	}
	return true
}

func PrefixSki(ski []byte, prefix string) (pski []byte) {
	if prefix != "ECDSA" && prefix != "SM2" && prefix != "RSA" {
		//logger.Warning("Not a valid prefix for ski, must be ECDSA SM2 or RSA")
		fmt.Println("Not a valid prefix for ski, must be ECDSA SM2 or RSA")
	}
	prefixBytes := []byte(prefix)
	pski = make([]byte, len(ski)+len(prefixBytes))
	copy(pski, prefixBytes)
	copy(pski[len(prefixBytes):], ski)

	return pski
}
