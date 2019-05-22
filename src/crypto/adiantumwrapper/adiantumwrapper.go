package adiantumwrapper

import (
	"crypto"
	"crypto/lukechampine/adiantum"
	"crypto/lukechampine/adiantum/hbsh"
)

const BlockSize = 8

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 8 {
		return nil, KeySizeError(len(key))
	}

	c := new(desCipher)
	c.generateSubkeys(key)
	return c, nil
}

func (c *desCipher) BlockSize() int { return BlockSize }

func (c *desCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/des: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/des: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/des: invalid buffer overlap")
	}
	encryptBlock(c.subkeys[:], dst, src)
}

func (c *desCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/des: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/des: output not full block")
	}
	if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/des: invalid buffer overlap")
	}
	decryptBlock(c.subkeys[:], dst, src)
}