// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmts "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/dlnp"
	"github.com/binance-chain/tss-lib/crypto/vss"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if err := round.ValidateParams(); err != nil {
		return round.WrapError(*err)
	}
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 1. calculate "partial" key share ui
	ui := common.GetRandomPositiveInt(tss.EC().Params().N)

	round.temp.ui = ui

	// 2. compute the vss shares
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(tss.EC(), round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.save.Ks = ids

	// security: the original u_i may be discarded
	ui = zero // clears the secret data from memory
	_ = ui    // silences a linter warning

	// make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	cmt := cmts.NewHashCommitment(pGFlat...)

	// 4. generate Paillier public key E_i, private key and proof
	// 5-7. generate safe primes for ZKPs used later on
	// 9-11. compute ntilde, h1, h2 (uses safe primes)
	// use the pre-params if they were provided to the LocalParty constructor
	var preParams *LocalPreParams
	if round.save.LocalPreParams.Validate() && !round.save.LocalPreParams.ValidateWithProof() {
		return round.WrapError(
			errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib"))
	} else if round.save.LocalPreParams.ValidateWithProof() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = GeneratePreParams(round.SafePrimeGenTimeout(), 3)
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}

	// Sign the Paillier PK
	r, s, err := ecdsa.Sign(rand.Reader, (*ecdsa.PrivateKey)(preParams.AuthEcdsaPrivateKey),
		ecdsautils.HashPaillierKey(&preParams.PaillierSK.PublicKey))
	if err != nil {
		return round.WrapError(errors.New("ecdsa signature for authentication failed"), Pi)
	}
	authPaillierSignaturei := ecdsautils.NewECDSASignature(r, s)
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i

	// generate the dlnproofs for keygen
	h1i, h2i, alpha, beta, p, q, NTildei :=
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.Beta,
		preParams.P,
		preParams.Q,
		preParams.NTildei

	randIntProofNSquareFreei, proofNSquareFree := ecdsautils.ProofNSquareFree(NTildei, p, q)

	dlnProof1 := dlnp.NewProof(h1i, h2i, alpha, p, q, NTildei)
	dlnProof2 := dlnp.NewProof(h2i, h1i, beta, p, q, NTildei)

	// for this P: SAVE
	// - shareID
	// and keep in temporary storage:
	// - VSS Vs
	// - our set of Shamir shares
	round.save.ShareID = ids[i]
	round.temp.vs = vs
	round.temp.shares = shares

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.PaillierSK = preParams.PaillierSK
	round.save.AuthEcdsaPrivateKey = preParams.AuthEcdsaPrivateKey
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	round.temp.deCommitPolyG = cmt.D

	// BROADCAST commitments, paillier pk + proof; round 1 message
	{
		msg, err := NewKGRound1Message(
			round.PartyID(), cmt.C, &preParams.PaillierSK.PublicKey,
			&preParams.AuthEcdsaPrivateKey.PublicKey,
			authPaillierSignaturei,
			preParams.NTildei, preParams.H1i, preParams.H2i,
			proofNSquareFree, randIntProofNSquareFreei, dlnProof1, dlnProof2)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		round.temp.kgRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
