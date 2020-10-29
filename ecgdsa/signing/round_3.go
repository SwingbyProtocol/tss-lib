// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()
	modN := common.ModInt(tss.EC().Params().N)

	// 1. get the local k_i
	kx, ky := tss.EC().ScalarBaseMult(round.temp.ki.Bytes())

	// 2-6. compute k
	i := round.PartyID().Index
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 2 {
			return round.WrapError(errors.New("length of de-commitment should be 2"))
		}

		kj, err := crypto.NewECPoint(tss.EC(), coordinates[0], coordinates[1])
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(kj)"), Pj)
		}
		proof, err := r2msg.UnmarshalZKProof()
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal kj proof"), Pj)
		}
		ok = proof.Verify(kj)
		if !ok {
			return round.WrapError(errors.New("failed to prove kj"), Pj)
		}

		kx, ky = tss.EC().Add(kx, ky, kj.X(), kj.Y())
	}

	// 7. compute qpoint =g^k
	qPoint := schnorr.CurvePoint{
		X: kx,
		Y: ky,
	}
	pubkeybytes := round.key.ECGDSAPub.SerializeCompressed()
	// rvalue=h(q||pubkey||m)
	rvalueBytes := common.SHA512_256(qPoint.SerializeCompressed(), pubkeybytes, round.temp.m.Bytes())
	rvalue := new(big.Int).Mod(new(big.Int).SetBytes(rvalueBytes), tss.EC().Params().N)
	rvalue = rvalue.Mod(rvalue, tss.EC().Params().N)

	// 8. compute si=ki+sk*r
	si := modN.Add(round.temp.ki, modN.Mul(round.temp.wi, rvalue))

	// 9. store r3 message pieces r= k_1+.....k_i
	round.temp.si = si

	// clean up the secret and the ri
	round.temp.wi = zero
	round.temp.ki = zero
	// 9. generate the random value for share proof
	li := common.GetRandomPositiveInt(tss.EC().Params().N)  // li
	roI := common.GetRandomPositiveInt(tss.EC().Params().N) // pi
	gToSi := crypto.ScalarBaseMult(tss.EC(), si)            // g^s_i
	liPoint := crypto.ScalarBaseMult(tss.EC(), li)

	// compute A_i=g^(ro_i)
	bigAi := crypto.ScalarBaseMult(tss.EC(), roI)
	// compute g^(li)g^(s_i)
	bigVi, err := gToSi.Add(liPoint)
	if err != nil {
		return round.WrapError(errors.Wrapf(err, "rToSi.Add(li)"))
	}

	cmt := commitments.NewHashCommitment(bigVi.X(), bigVi.Y(), bigAi.X(), bigAi.Y())
	r3msg := NewSignRound3Message(round.PartyID(), cmt.C)

	// calculate the R^(-1)
	minusOne := new(big.Int).Mod(big.NewInt(-1), tss.EC().Params().N)
	x, y := tss.EC().ScalarMult(qPoint.X, qPoint.Y, minusOne.Bytes())
	bigMinusQ, err := crypto.NewECPoint(tss.EC(), x, y)
	if err != nil {
		return round.WrapError(errors.Wrapf(err, "cannot map the R-1 to curve"))
	}

	// 10. broadcast si to other parties
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	// 11. store r3 message pieces
	round.temp.si = si
	// in ecgdsa r and h are the same value
	round.temp.r = rvalue
	round.temp.h = rvalue
	round.temp.qPoint = qPoint
	round.temp.li = li
	round.temp.bigAi = bigAi
	round.temp.bigVi = bigVi
	round.temp.roi = roI
	round.temp.bigMinusQ = bigMinusQ
	round.temp.DPower = cmt.D
	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
