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

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

func encoded32BytesToBigInt(s []byte) *big.Int {
	if len(s) > 32 {
		panic(fmt.Errorf("encoded32BytesToBigInt expected <= 32 bytes but got %d", len(s)))
	}
	sCopy := make([]byte, 0, 32)
	copy(sCopy, s)
	reverse(sCopy)
	return new(big.Int).SetBytes(sCopy)
}

func bigIntToEncodedBytes32(a *big.Int) []byte {
	if len(a.Bytes()) > 32 {
		panic(fmt.Errorf("bigIntToEncodedBytes32 expected <= 32 bytes but got %d", len(a.Bytes())))
	}
	var s []byte
	if a == nil {
		panic("a == nil in bigIntToEncodedBytes32")
	}
	s = copyBytes32(a.Bytes())
	// reverse to become little endian
	return reverse(s)
}

func ecPointToEncodedBytes32(x *big.Int) ([]byte, error) {
	var err error
	fe := new(field.Element)
	xB := bigIntToEncodedBytes32(x)
	if fe, err = fe.SetBytes(xB); err != nil {
		return nil, err
	}
	return fe.Bytes(), nil
}

func copyBytes32(aB []byte) []byte {
	if aB == nil {
		return nil
	}
	s := make([]byte, 32)
	// if short, expand it so that it's long enough
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

func addExtendedElements(p, q *edwards25519.Point) (*edwards25519.Point, error) {
	new(edwards25519.Point).Add(p, q)
	PX, PY, PZ, PT := p.ExtendedCoordinates()
	QX, QY, QZ, QT := q.ExtendedCoordinates()
	return new(edwards25519.Point).SetExtendedCoordinates(
		new(field.Element).Add(PX, QX),
		new(field.Element).Add(PY, QY),
		new(field.Element).Add(PZ, QZ),
		new(field.Element).Add(PT, QT))
}

func OddY(a *crypto.ECPoint) bool {
	return a.Y().Bit(0) > 0
}

func SchnorrVerify(p *btcec.PublicKey, m []byte, r_ *big.Int, s_ *big.Int) bool {
	var r secp256k1.FieldVal
	var s secp256k1.ModNScalar
	r.SetByteSlice(r_.Bytes())
	s.SetByteSlice(s_.Bytes())
	err := schnorrVerify(m, p, r, s)
	return err == nil
}

func schnorrVerify(hash []byte, pubKey *btcec.PublicKey, sigR secp256k1.FieldVal, sigS secp256k1.ModNScalar) error {
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

func reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
