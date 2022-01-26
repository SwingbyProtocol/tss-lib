// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func encodedBytesToBigInt(s *[32]byte) *big.Int {
	// Use a copy so we don't screw up our original
	// memory.
	sCopy := new([32]byte)
	for i := 0; i < 32; i++ {
		sCopy[i] = s[i]
	}
	reverse(sCopy)

	bi := new(big.Int).SetBytes(sCopy[:])

	return bi
}

func bigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}

	// Caveat: a can be longer than 32 bytes.
	s = copyBytes(a.Bytes())

	// Reverse the byte string --> little endian after
	// encoding.
	reverse(s)

	return s
}

func copyBytes(aB []byte) *[32]byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 32 {
		diff := 32 - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < 32; i++ {
		s[i] = aB[i]
	}

	return s
}

func ecPointToEncodedBytes(x *big.Int, y *big.Int) *[32]byte {
	s := bigIntToEncodedBytes(y)
	xB := bigIntToEncodedBytes(x)
	xFE := new(edwards25519.FieldElement)
	edwards25519.FeFromBytes(xFE, xB)
	isNegative := edwards25519.FeIsNegative(xFE) == 1

	if isNegative {
		s[31] |= (1 << 7)
	} else {
		s[31] &^= (1 << 7)
	}

	return s
}

func reverse(s *[32]byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func addExtendedElements(p, q edwards25519.ExtendedGroupElement) edwards25519.ExtendedGroupElement {
	var r edwards25519.CompletedGroupElement
	var qCached edwards25519.CachedGroupElement
	q.ToCached(&qCached)
	edwards25519.GeAdd(&r, &p, &qCached)
	var result edwards25519.ExtendedGroupElement
	r.ToExtended(&result)
	return result
}

func ecPointToExtendedElement(ec elliptic.Curve, x *big.Int, y *big.Int) edwards25519.ExtendedGroupElement {
	encodedXBytes := bigIntToEncodedBytes(x)
	encodedYBytes := bigIntToEncodedBytes(y)

	z := common.GetRandomPositiveInt(ec.Params().N)
	encodedZBytes := bigIntToEncodedBytes(z)

	var fx, fy, fxy edwards25519.FieldElement
	edwards25519.FeFromBytes(&fx, encodedXBytes)
	edwards25519.FeFromBytes(&fy, encodedYBytes)

	var X, Y, Z, T edwards25519.FieldElement
	edwards25519.FeFromBytes(&Z, encodedZBytes)

	edwards25519.FeMul(&X, &fx, &Z)
	edwards25519.FeMul(&Y, &fy, &Z)
	edwards25519.FeMul(&fxy, &fx, &fy)
	edwards25519.FeMul(&T, &fxy, &Z)

	return edwards25519.ExtendedGroupElement{
		X: X,
		Y: Y,
		Z: Z,
		T: T,
	}
}

func OddY(a *crypto.ECPoint) bool {
	return a.Y().Bit(0) > 0
}

func SchnorrVerify(p *btcec.PublicKey, m []byte, r_ *big.Int, s_ *big.Int) bool {
	var r btcec.FieldVal
	var s btcec.ModNScalar
	r.SetByteSlice(r_.Bytes())
	s.SetByteSlice(s_.Bytes())
	err := schnorrVerify(m, p, r, s)
	return err == nil
}

func schnorrVerify(hash []byte, pub *btcec.PublicKey, sigR btcec.FieldVal, sigS btcec.ModNScalar) error {
	// The algorithm for producing a BIP-340 signature is described in
	// README.md and is reproduced here for reference:
	//
	// 1. Fail if m is not 32 bytes
	// 2. P = lift_x(int(pk)).
	// 3. r = int(sig[0:32]); fail is r >= p.
	// 4. s = int(sig[32:64]); fail if s >= n.
	// 5. e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || M)) mod n.
	// 6. R = s*G - e*P
	// 7. Fail if is_infinite(R)
	// 8. Fail if not hash_even_y(R)
	// 9. Fail is x(R) != r.
	// 10. Return success iff not failure occured before reachign this
	// point.

	// Step 1.
	//
	// Fail if m is not 32 bytes
	if len(hash) != 32 {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(hash), 32)
		return schnorr.Error{Err: schnorr.ErrorKind("ErrInvalidHashLen"), Description: str}
	}

	// Before we proceed, we want to ensure that the public key we're using
	// for verification always has an even y-coordinate. So we'll serialize
	// it, then parse it again to esure we only proceed with points that
	// have an even y-coordinate.
	pubKey, err := ParsePubKey(pub.SerializeCompressed()[1:])
	if err != nil {
		return err
	}
	pubKey = pub // extra

	// Step 2.
	//
	// Fail if Q is not a point on the curve
	if !pubKey.IsOnCurve() {
		str := "pubkey point is not on curve"
		return schnorr.Error{Err: schnorr.ErrorKind("ErrPubKeyNotOnCurve"), Description: str}
	}

	// Step 3.
	//
	// Fail if r >= p
	//
	// Note this is already handled by the fact r is a field element.

	// Step 4.
	//
	// Fail if s >= n
	//
	// Note this is already handled by the fact s is a mod n scalar.

	// Step 5.
	//
	// e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || M)) mod n.
	var rBytes [32]byte
	sigR.PutBytesUnchecked(rBytes[:])
	pBytes := pubKey.SerializeCompressed()

	logBytes("finalize schnorrVerify - ", rBytes[:], pBytes[1:], hash)
	common.Logger.Debugf("finalize schnorrVerify - sigR: %v", sigR.String())
	commitment := chainhash.TaggedHash(
		[]byte("BIP0340/challenge"), rBytes[:], pBytes[1:], hash,
	)

	var e btcec.ModNScalar
	if overflow := e.SetBytes((*[32]byte)(commitment)); overflow != 0 {
		str := "hash of (r || P || m) too big"
		return schnorr.Error{Err: schnorr.ErrorKind("ErrSchnorrHashValue"), Description: str}
	}

	common.Logger.Debugf("finalize schnorrVerify - e: %v", e.String())

	// Negate e here so we can use AddNonConst below to subtract the s*G
	// point from e*P.
	e.Negate()

	// Step 6.
	//
	// R = s*G - e*P
	var P, R, sG, eP btcec.JacobianPoint
	pubKey.AsJacobian(&P)
	btcec.ScalarBaseMultNonConst(&sigS, &sG)
	btcec.ScalarMultNonConst(&e, &P, &eP)

	var _sGAffine btcec.JacobianPoint
	_sGAffine.X, _sGAffine.Y, _sGAffine.Z = sG.X, sG.Y, sG.Z
	_sGAffine.ToAffine()

	var _ePAffine btcec.JacobianPoint
	_ePAffine.X, _ePAffine.Y, _ePAffine.Z = eP.X, eP.Y, eP.Z
	_ePAffine.ToAffine()
	common.Logger.Debugf("finalize - (minus)e: %v, P: %v, _sGAffine: %v, -ePAffine: %v", e.String(),
		JacobianPointToString(P),
		JacobianPointToString(_sGAffine),
		JacobianPointToString(_ePAffine))
	btcec.AddNonConst(&sG, &eP, &R)

	// Step 7.
	//
	// Fail if R is the point at infinity
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		str := "calculated R point is the point at infinity"
		return schnorr.Error{Err: schnorr.ErrorKind("ErrSigRNotOnCurve"), Description: str}
	}

	// Step 8.
	//
	// Fail if R.y is odd
	//
	// Note that R must be in affine coordinates for this check.
	R.ToAffine()
	common.Logger.Debugf("finalize - R (calculated) (after affine): %v", JacobianPointToString(R))
	if R.Y.IsOdd() {
		str := "calculated R y-value is odd"
		return schnorr.Error{Err: schnorr.ErrorKind("ErrSigRYIsOdd"), Description: str}
	}

	// Step 9.
	//
	// Verified if R.x == r
	//
	// Note that R must be in affine coordinates for this check.
	common.Logger.Debugf("sigR: %s, R.X (calculated): %s", sigR.String(), R.X.String())
	if !sigR.Equals(&R.X) {
		str := "calculated R point was not given R"
		return schnorr.Error{Err: schnorr.ErrorKind("ErrUnequalRValues"), Description: str}
	}

	// Step 10.
	//
	// Return success iff not failure occured before reachign this
	return nil
}

func logBytes(logMsg string, r, p, h []byte) {
	common.Logger.Debugf("%s r: %s, p: %s, h: %s", logMsg, hex.EncodeToString(r), hex.EncodeToString(p), hex.EncodeToString(h))
}

func JacobianPointToString(point secp256k1.JacobianPoint) string {
	return "[X:" + point.X.String() + ", Y:" + point.Y.String() + ", Z:" + point.Z.String() + "]"
}

func ParsePubKey(pubKeyStr []byte) (*btcec.PublicKey, error) {
	if pubKeyStr == nil {
		err := fmt.Errorf("nil pubkey byte string")
		return nil, err
	}
	if len(pubKeyStr) != 32 {
		err := fmt.Errorf("bad pubkey byte string size (want %v, have %v)",
			32, len(pubKeyStr))
		return nil, err
	}

	// We'll manually prepend the compressed byte so we can re-use the
	// existing pubkey parsing routine of the main btcec package.
	var keyCompressed [btcec.PubKeyBytesLenCompressed]byte
	keyCompressed[0] = btcec.PubKeyFormatCompressedEven
	copy(keyCompressed[1:], pubKeyStr)

	return btcec.ParsePubKey(keyCompressed[:])
}

func RSBytesToBtcec(r_ []byte, s_ []byte) (btcec.FieldVal, btcec.ModNScalar) {
	var r btcec.FieldVal
	var s btcec.ModNScalar
	r.SetByteSlice(r_)
	s.SetByteSlice(s_)
	return r, s
}

func RSToSchnorrSignature(r_ *big.Int, s_ *big.Int) *schnorr.Signature {
	var r btcec.FieldVal
	var s btcec.ModNScalar
	r.SetByteSlice(r_.Bytes())
	s.SetByteSlice(s_.Bytes())
	signature := schnorr.NewSignature(&r, &s)
	return signature
}

func RSByesToSchnorrSignature(r_ []byte, s_ []byte) *schnorr.Signature {
	var r btcec.FieldVal
	var s btcec.ModNScalar
	r.SetByteSlice(r_)
	s.SetByteSlice(s_)
	return schnorr.NewSignature(&r, &s)
}

func NextPointEvenY(curve elliptic.Curve, P *crypto.ECPoint) (*crypto.ECPoint, int) {
	G := crypto.ScalarBaseMult(curve, big.NewInt(1))
	a := 0
	Q := *P
	Qptr := &Q
	for ; OddY(Qptr); a++ { // Y cannot be odd
		Qptr, _ = Qptr.Add(G)
	}
	return Qptr, a
}
