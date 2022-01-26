// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
)

func AliceInit(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	a, cA, rA, NTildeB, h1B, h2B *big.Int,
) (pf *RangeProofAlice, err error) {
	return ProveRangeAlice(ec, pkA, cA, NTildeB, h1B, h2B, a, rA)
}

func BobMid(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
) (beta, cB, betaPrm *big.Int, piB *ProofBob, err error) {
	if !pf.Verify(ec, pkA, NTildeB, h1B, h2B, cA) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}
	q := ec.Params().N
	betaPrm = common.GetRandomPositiveInt(pkA.N)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	if cB, err = pkA.HomoMult(b, cA); err != nil {
		return
	}
	if cB, err = pkA.HomoAdd(cB, cBetaPrm); err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBob(ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand)
	return
}

func BobMidWC(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	B *crypto.ECPoint,
) (betaPrm, cB *big.Int, piB *ProofBobWC, err error) {
	if !pf.Verify(ec, pkA, NTildeB, h1B, h2B, cA) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}
	betaPrm = common.GetRandomPositiveInt(pkA.N)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	piB, err = ProveBobWC(ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, B)
	return
}

func AliceEnd(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBob,
	h1A, h2A, cA, cB, NTildeA *big.Int,
	sk *paillier.PrivateKey,
) (alphaIJ *big.Int, err error) {
	if !pf.Verify(ec, pkA, NTildeA, h1A, h2A, cA, cB) {
		err = errors.New("ProofBob.Verify() returned false")
		return
	}
	if alphaIJ, err = sk.Decrypt(cB); err != nil {
		return
	}
	q := ec.Params().N
	alphaIJ.Mod(alphaIJ, q)
	return
}

func AliceEndWC(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBobWC,
	B *crypto.ECPoint,
	cA, cB, NTildeA, h1A, h2A *big.Int,
	sk *paillier.PrivateKey,
) (muIJ, muIJRec, muIJRand *big.Int, err error) {
	if !pf.Verify(ec, pkA, NTildeA, h1A, h2A, cA, cB, B) {
		err = errors.New("ProofBobWC.Verify() returned false")
		return
	}
	if muIJRec, muIJRand, err = sk.DecryptAndRecoverRandomness(cB); err != nil {
		return
	}
	q := ec.Params().N
	muIJ = new(big.Int).Mod(muIJRec, q)
	return
}
