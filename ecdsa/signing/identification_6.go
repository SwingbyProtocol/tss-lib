// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkpmul "github.com/binance-chain/tss-lib/crypto/zkp/mul"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func newRound6(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &identification6{&identificationPrep{&sign4{&presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 3}}}}, false}}}
}

func (round *identification6) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	common.Logger.Debugf("party %v, identification6 Start", round.PartyID())
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true
	q := round.EC().Params().N
	/* var modMul = func(N, a, b *big.Int) *big.Int {
		_N := common.ModInt(big.NewInt(0).Set(N))
		return _N.Mul(a, b)
	} */
	var modQ3Mul = func(a, b *big.Int) *big.Int {
		q3 := common.ModInt(new(big.Int).Mul(q, new(big.Int).Mul(q, q)))
		return q3.Mul(a, b)
	}
	var modN = func(a *big.Int) *big.Int {
		m := common.ModInt(round.EC().Params().N)
		return m.Add(zero, a)
	}
	/* var q3Add = func(a, b *big.Int) * big.Int {
		q3 := new(big.Int).Mul(q, new(big.Int).Mul(q, q))
		return q3.Add(a, b)
	} */

	// Fig 7. Output.2
	H, _ := round.key.PaillierSK.HomoMult(round.temp.ki, round.temp.G)
	proofH, errM := zkpmul.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, round.temp.G, H, round.temp.ki, round.temp.𝜌i)
	if errM != nil {
		return round.WrapError(fmt.Errorf("error creating zkp"))
	}
	if !proofH.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, round.temp.G, H) {
		return round.WrapError(fmt.Errorf("error in zkp verification"))
	}
	DeltaShareEnc := H
	secretProduct := big.NewInt(1).Exp(round.temp.𝜈i, round.temp.ki, round.key.PaillierSK.PublicKey.NSquare())
	encryptedValueSum := modQ3Mul(round.temp.ki,round.temp.𝛾i)

	proof1, errD := zkpdec.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, H, modN(encryptedValueSum), round.key.NTildei, round.key.H1i, round.key.H2i, encryptedValueSum, secretProduct)
	if errD != nil {
		return round.WrapError(fmt.Errorf("error creating zkp"))
	}
	okD := proof1.Verify(round.EC(), &round.key.PaillierSK.PublicKey, H, modN(encryptedValueSum), round.key.NTildei, round.key.H1i, round.key.H2i)
    common.Logger.Debugf("party r6, okD? %v", round.PartyID(), okD)

	var errH1, errH2 error
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}

		DeltaShareEnc, errH1 = round.key.PaillierSK.HomoAdd(DeltaShareEnc, round.temp.r2msgDeltaD[j])
		if errH1 != nil {
			return round.WrapError(fmt.Errorf("error with addition"))
		}
		DeltaShareEnc, errH2 = round.key.PaillierSK.HomoAdd(DeltaShareEnc, round.temp.Dji[j])
		if errH2 != nil {
			return round.WrapError(fmt.Errorf("error with addition"))
		}
	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		common.Logger.Debugf("party: %v, r6 NewProof j: %v, PK: %v, DeltaShareEnc(C): %v, 𝛿i(x): %v, NTildej(NCap): %v, " +
			"H1j(s): %v, H2j(t): %v, 𝛿i(y): %v, 𝜈i: %v",
			round.PartyID(), j, common.FormatBigInt(round.key.PaillierSK.PublicKey.N),
			common.FormatBigInt(DeltaShareEnc),
			common.FormatBigInt(round.temp.𝛿i),
			common.FormatBigInt(round.key.NTildej[j]), common.FormatBigInt(round.key.H1j[j]), common.FormatBigInt(round.key.H2j[j]),
			common.FormatBigInt(round.temp.𝛿i), common.FormatBigInt(round.temp.𝜈i))
		proofDeltaShare, errD := zkpdec.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, DeltaShareEnc, round.temp.𝛿i, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.𝛿i, round.temp.𝜈i)
		if errD != nil {
			return round.WrapError(fmt.Errorf("error with proof"))
		}
		ok := proofDeltaShare.Verify(round.EC(), &round.key.PaillierSK.PublicKey, DeltaShareEnc, round.temp.𝛿i, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j]) // TODO
		if !ok { // gf TODO
			common.Logger.Errorf("party %v, j: %v, error in verify ***", round.PartyID(), j)
		} else {
			common.Logger.Errorf("party %v, j: %v,  verify ok! ***", round.PartyID(), j)
		}
		r6msg := NewIdentificationRound6Message(Pj, round.PartyID(), H, proofH, DeltaShareEnc, proofDeltaShare)
		common.Logger.Debugf("party %v, r6, Pj: %v NewIdentificationRound6Message going out", round.PartyID(), Pj)
		round.out <- r6msg
	}

	// retire unused variables
	round.temp.K = nil
	round.temp.𝛾i = nil
	round.temp.r2msgDeltaD = make([]*big.Int, round.PartyCount())
	round.temp.r2msgDeltaF = make([]*big.Int, round.PartyCount())
	return nil
}

func (round *identification6) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r6msgH {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *identification6) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*IdentificationRound6Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *identification6) NextRound() tss.Round {
	round.started = false
	return &identification7{round}
}
