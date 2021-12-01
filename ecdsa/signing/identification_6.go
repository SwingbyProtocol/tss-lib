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
	var modMul = func(N, a, b *big.Int) *big.Int {
		_N := common.ModInt(big.NewInt(0).Set(N))
		return _N.Mul(a, b)
	}
	var q3Add = func(a, b *big.Int) *big.Int {
		q3 := new(big.Int).Mul(q, new(big.Int).Mul(q, q))
		return q3.Add(a, b)
	}

	// Fig 7. Output.2
	Hi, _ := round.key.PaillierSK.HomoMult(round.temp.ki, round.temp.G)
	proofHMul, errM := zkpmul.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, round.temp.G, Hi, round.temp.ki, round.temp.𝜌i)
	if errM != nil {
		return round.WrapError(fmt.Errorf("error creating zkp"))
	}
	if !proofHMul.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, round.temp.G, Hi) {
		return round.WrapError(fmt.Errorf("error in zkp verification"))
	}
	DeltaShareEnc := Hi
	secretProduct := big.NewInt(1).Exp(round.temp.𝜈i, round.temp.ki, round.key.PaillierSK.PublicKey.NSquare())
	encryptedValueSum := modQ3Mul(round.temp.ki, round.temp.𝛾i)

	proofHDec, errHDec := zkpdec.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, Hi, modN(encryptedValueSum),
		round.key.NTildei, round.key.H1i, round.key.H2i, encryptedValueSum, secretProduct)
	if errHDec != nil {
		return round.WrapError(fmt.Errorf("error creating zkp"))
	}
	okHDec := proofHDec.Verify(round.EC(), &round.key.PaillierSK.PublicKey, Hi, modN(encryptedValueSum), round.key.NTildei, round.key.H1i, round.key.H2i)
	if !okHDec {
		return round.WrapError(errors.New("error in zkp verification"))
	}
	pkiNSquare := round.key.PaillierSK.PublicKey.NSquare()
	var errDSE error
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		DF, errDF := round.key.PaillierSK.PublicKey.HomoAdd(round.temp.r2msgDeltaD[j], round.temp.DeltaMtAFji[j])
		if errDF != nil {
			return round.WrapError(fmt.Errorf("error with addition"))
		}

		{
			𝛾j := round.temp.r5msg𝛾j[j]
			𝜌𝛾s := modMul(pkiNSquare, big.NewInt(1).Exp(round.temp.𝜌i, 𝛾j, pkiNSquare), round.temp.r5msgsji[j])
			𝛽ʹ := round.temp.r5msg𝛽ʹji[j]
			𝛽ij := round.temp.DeltaShareBetas[j]
			𝛾k𝛽ʹ := q3Add(𝛽ʹ, modQ3Mul(𝛾j, round.temp.ki))
			{
				proofD, errD := zkpdec.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.r2msgDeltaD[j],
					modN(𝛾k𝛽ʹ), round.key.NTildei, round.key.H1i, round.key.H2i, 𝛾k𝛽ʹ, 𝜌𝛾s)
				/* common.Logger.Debugf("r6 zkpdecNewProof D(i%v,j:%v): %v, 𝛽ji: %v, DeltaShareBetas[j]: %v, 𝛽ʹji:%v, sji:%v, 𝛾k𝛽ʹ:%v, 𝜌𝛾s: %v, 𝛾j:%v", i, j, common.FormatBigInt(round.temp.r2msgDeltaD[j]),
				common.FormatBigInt(𝛽ji), common.FormatBigInt(round.temp.DeltaShareBetas[j]), common.FormatBigInt(𝛽ʹ), common.FormatBigInt(round.temp.r5msgsji[j]),
				common.FormatBigInt(𝛾k𝛽ʹ) , common.FormatBigInt(𝜌𝛾s), common.FormatBigInt(𝛾j)) */
				if errD != nil {
					return round.WrapError(fmt.Errorf("error creating zkp"))
				}
				okD := proofD.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.r2msgDeltaD[j],
					modN(𝛾k𝛽ʹ), round.key.NTildei, round.key.H1i, round.key.H2i)
				if !okD {
					return round.WrapError(errors.New(fmt.Sprintf("error in zkp verification - current party(i):%v, other party(j):%v",
						round.PartyID(), Pj)))
				}
			}

			/* common.Logger.Debugf("r6 F(j%v,i%v): %v, 𝛽ʹij: %v, rij:%v", j, i, common.FormatBigInt(round.temp.DeltaMtAFji[j]),
			common.FormatBigInt(𝛽ʹ), common.FormatBigInt(round.temp.DeltaMtARij[j])) */

			𝜌𝛾sr := modMul(pkiNSquare, 𝜌𝛾s, round.temp.DeltaMtARij[j])
			𝛾k𝛽ʹ𝛽 := q3Add(𝛾k𝛽ʹ, 𝛽ij)

			/* common.Logger.Debugf("r6 zkpdecNewProof DF(i:%v,j:%v): %v, rij: %v, 𝛾k𝛽ʹ𝛽:%v, 𝛾k𝛽ʹ:%v, 𝛽ji:%v, 𝜌𝛾sr:%v", i, j, common.FormatBigInt(DF),
			common.FormatBigInt(round.temp.DeltaMtARij[j]), common.FormatBigInt(𝛾k𝛽ʹ𝛽),
			common.FormatBigInt(𝛾k𝛽ʹ), common.FormatBigInt(𝛽ij),
			common.FormatBigInt(𝜌𝛾sr)) */

			proof, errP := zkpdec.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, DF,
				common.ModInt(round.EC().Params().N).Add(zero, 𝛾k𝛽ʹ𝛽), round.key.NTildei, round.key.H1i, round.key.H2i, 𝛾k𝛽ʹ𝛽, 𝜌𝛾sr)
			if errP != nil {
				return round.WrapError(fmt.Errorf("identification of aborts - error with zk proof"), Pj)
			}
			if ok := proof.Verify(round.EC(), &round.key.PaillierSK.PublicKey, DF,
				common.ModInt(round.EC().Params().N).Add(zero, 𝛾k𝛽ʹ𝛽), round.key.NTildei, round.key.H1i, round.key.H2i); !ok {
				return round.WrapError(fmt.Errorf("identification of aborts - error with zk proof"), Pj)
			}

			secretProduct = modMul(round.key.PaillierSK.PublicKey.NSquare(), 𝜌𝛾sr, secretProduct)
			encryptedValueSum = q3Add(𝛾k𝛽ʹ𝛽, encryptedValueSum)
		}

		DeltaShareEnc, errDSE = round.key.PaillierSK.PublicKey.HomoAdd(DF, DeltaShareEnc)
		if errDSE != nil {
			return round.WrapError(fmt.Errorf("identification of aborts - error with addition"), Pj)
		}
	}
	/* common.Logger.Debugf("r6 zkpdecNewProof i:%v, DeltaShareEnc: %v, encryptedValueSum: %v, secretProduct: %v", i,
	common.FormatBigInt(DeltaShareEnc), common.FormatBigInt(encryptedValueSum), common.FormatBigInt(secretProduct)) */

	proofDeltaShare, errS := zkpdec.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, DeltaShareEnc,
		modN(encryptedValueSum), round.key.NTildei, round.key.H1i, round.key.H2i, encryptedValueSum, secretProduct)
	if errS != nil {
		return round.WrapError(fmt.Errorf("error in zkpdec"))
	}

	r6msg := NewIdentificationRound6Message(round.PartyID(), Hi, proofHMul, DeltaShareEnc, encryptedValueSum, proofDeltaShare)
	round.out <- r6msg

	// retire unused variables
	round.temp.K = nil
	round.temp.r2msgDeltaD = make([]*big.Int, round.PartyCount())
	round.temp.r2msgDeltaF = make([]*big.Int, round.PartyCount())
	round.temp.r2msgDeltaFjiPki = make([]*big.Int, round.PartyCount())
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
		return msg.IsBroadcast()
	}
	return false
}

func (round *identification6) NextRound() tss.Round {
	round.started = false
	return &identification7{round}
}
