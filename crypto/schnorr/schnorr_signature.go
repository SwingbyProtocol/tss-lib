// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr

import (
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec"

	"github.com/binance-chain/tss-lib/common"
)

const (
	PubKeyBytesLenCompressed   = 33
	PubKeyBytesLenUncompressed = 65
	PubKeyBytesLenHybrid       = 65

	pubkeyCompressed   byte = 0x2 // y_bit + x coord
	pubkeyUncompressed byte = 0x4 // x coord + y coord
)

var (
	one  = big.NewInt(1)
	zero = big.NewInt(0)
)

// PublicKey represents an ECGSA public key.
type PublicKey struct {
	X, Y *big.Int
}

type CurvePoint PublicKey

func (p CurvePoint) SerializeCompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

// PrivateKey represents an ECGSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

type EcgdsaSignature struct {
	R, S *big.Int
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// SerializeCompressed serializes a public key in a 33-byte compressed format.
func (p *PublicKey) SerializeCompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

// SerializeUncompressed serializes a public key in a 65-byte uncompressed
// format.
func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

func ParseSignature(in []byte) (EcgdsaSignature, error) {
	if len(in) != 64 {
		return EcgdsaSignature{}, errors.New("invalid signature")
	}
	r := new(big.Int).SetBytes(in[:32])
	s := new(big.Int).SetBytes(in[32:])
	sig := EcgdsaSignature{
		r,
		s,
	}
	return sig, nil
}

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func (sk *PrivateKey) Sign(msgHash []byte) (EcgdsaSignature, error) {
	// get the random value for k
	c := btcec.S256()
	modN := common.ModInt(c.Params().N)
	k := common.GetRandomPositiveInt(c.Params().N)
	k = k.Mod(c.Params().N, k)
	qx, qy := c.ScalarBaseMult(k.Bytes())
	qPoint := PublicKey{
		qx,
		qy,
	}
	rBytes := common.SHA512_256(qPoint.SerializeCompressed(), sk.PublicKey.SerializeCompressed(), msgHash)
	r := new(big.Int).Mod(new(big.Int).SetBytes(rBytes), c.Params().N)
	// s=k+sk*r
	s := modN.Add(k, modN.Mul(sk.D, r))

	if big.NewInt(0).Cmp(r) == 0 || big.NewInt(0).Cmp(s) == 0 {
		return EcgdsaSignature{}, errors.New("fail to generate the signature")
	}

	sig := EcgdsaSignature{
		r,
		s,
	}
	return sig, nil
}

func (pub *PublicKey) Verify(msgHash []byte, r, s *big.Int) bool {
	c := btcec.S256()
	N := c.Params().N
	modN := common.ModInt(c.Params().N)
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	minR := modN.Sub(zero, r)

	rPAx, rPAy := c.ScalarMult(pub.X, pub.Y, minR.Bytes())
	sGx, sGy := c.ScalarBaseMult(s.Bytes())
	qvx, qvy := c.Add(rPAx, rPAy, sGx, sGy)

	qpoint := PublicKey{
		qvx,
		qvy,
	}
	rCalBytes := common.SHA512_256(qpoint.SerializeCompressed(), pub.SerializeCompressed(), msgHash)
	rCal := new(big.Int).Mod(new(big.Int).SetBytes(rCalBytes), c.Params().N)
	return r.Cmp(rCal) == 0
}
