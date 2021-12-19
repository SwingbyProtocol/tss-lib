// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/vss"
	zkpprm "github.com/binance-chain/tss-lib/crypto/zkp/prm"
	zkpsch "github.com/binance-chain/tss-lib/crypto/zkp/sch"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	// Fig 5. Round 1. private key part
	ridi := common.GetRandomPositiveInt(round.EC().Params().N)
	ui := common.GetRandomPositiveInt(round.EC().Params().N)

	// Fig 5. Round 1. pub key part, vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.Params().EC(), round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	xi := new(big.Int).Set(shares[i].Share)
	Xi := crypto.ScalarBaseMult(round.EC(), xi)
	Ai, τ, err := zkpsch.NewProofCommitment(Xi, xi)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// Fig 6. Round 1.
	var preParams *LocalPreParams
	if round.save.LocalPreParams.Validate() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = GeneratePreParams(round.SafePrimeGenTimeout())
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}

	P2, Q2 := new(big.Int).Lsh(preParams.P, 1), new(big.Int).Lsh(preParams.Q, 1)
	𝜑 := new(big.Int).Mul(P2, Q2)
	𝜓i, err := zkpprm.NewProof(preParams.H1i, preParams.H2i, preParams.NTildei, 𝜑, preParams.Beta)
	listToHash, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	listToHash = append(listToHash, preParams.PaillierSK.PublicKey.N, ridi, Xi.X(), Xi.Y(), Ai.X(), Ai.Y(), preParams.NTildei, preParams.H1i, preParams.H2i)
	for _, a := range 𝜓i.A {
		listToHash = append(listToHash, a)
	}
	for _, z := range 𝜓i.Z {
		listToHash = append(listToHash, z)
	}
	VHash := common.SHA512_256i(listToHash...)
	{
		msg := NewKGRound1Message(round.PartyID(), VHash)
		round.out <- msg
	}

	round.temp.𝜓i = 𝜓i
	round.temp.vs = vs
	round.temp.ridi = ridi
	round.temp.ui = ui
	round.temp.Ai = Ai
	round.temp.τ = τ
	round.save.Ks = ids
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i
	round.save.ShareID = ids[i]
	round.temp.shares = shares
	round.save.PaillierSK = preParams.PaillierSK
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r1msgVHashs {
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

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
