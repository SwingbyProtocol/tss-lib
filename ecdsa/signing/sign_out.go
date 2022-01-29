// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func VerirySig(ec elliptic.Curve, R *crypto.ECPoint, S *big.Int, m *big.Int, PK *crypto.ECPoint) bool {
	modN := common.ModInt(ec.Params().N)
	SInv := modN.Inverse(S)
	mG := crypto.ScalarBaseMult(ec, m)
	rx := R.X()
	rxPK := PK.ScalarMult(rx)
	R2, _ := mG.Add(rxPK)
	R2 = R2.ScalarMult(SInv)
	return R2.Equals(R)
}

func newRound5(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &signout{&sign4{&presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 5}}}}, false}}
}

func (round *signout) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	// Fig 8. Output. combine signature shares verify and output
	Sigma := round.temp.SigmaShare
	modN := common.ModInt(round.Params().EC().Params().N)
	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		Sigma = modN.Add(Sigma, round.temp.r4msg𝜎j[j])
	}
	recid := 0
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if round.temp.Rx.Cmp(round.Params().EC().Params().N) > 0 {
		recid = 2
	}
	if round.temp.BigR.Y().Bit(0) != 0 {
		recid |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	halfN := new(big.Int).Rsh(round.Params().EC().Params().N, 1)
	if Sigma.Cmp(halfN) > 0 {
		Sigma.Sub(round.Params().EC().Params().N, Sigma)
		recid ^= 1
	}

	// save the signature for final output
	bitSizeInBytes := round.Params().EC().Params().BitSize / 8
	round.data.R = common.PadToLengthBytesInPlace(round.temp.Rx.Bytes(), bitSizeInBytes)
	round.data.S = common.PadToLengthBytesInPlace(Sigma.Bytes(), bitSizeInBytes)
	round.data.Signature = append(round.data.R, round.data.S...)
	round.data.SignatureRecovery = []byte{byte(recid)}
	round.data.M = round.temp.m.Bytes()

	pk := ecdsa.PublicKey{
		Curve: round.Params().EC(),
		X:     round.key.ECDSAPub.X(),
		Y:     round.key.ECDSAPub.Y(),
	}
	ok := ecdsa.Verify(&pk, round.temp.m.Bytes(), round.temp.Rx, Sigma)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}

	round.end <- *round.data
	round.temp.G = nil
	round.temp.𝜈i = nil
	return nil
}

func (round *signout) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *signout) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *signout) NextRound() tss.Round {
	return nil // finished!
}
