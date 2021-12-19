// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func newRound4(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &sign4{&presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 4}}}}, false}
}

func (round *sign4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	common.Logger.Debugf("party %v sign4 Start", round.PartyID())
	round.resetOK()
	round.resetAborting()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Output.1 verify proof logstar
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			Kj := round.temp.r1msgK[j]
			Δj := round.temp.r3msgΔj[j]
			ψʺij := round.temp.r3msgProofLogstar[j]

			ok := ψʺij.Verify(round.EC(), round.key.PaillierPKs[j], Kj, Δj, round.temp.Γ, round.key.NTildei, round.key.H1i, round.key.H2i)
			if !ok {
				common.Logger.Errorf("zkplogstar proof verify failed - this party(i): %v, culprit(Pj): %v", i, Pj)
				errChs <- round.WrapError(errors.New("proof verify failed"), Pj)
				return
			}
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0)
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to verify proofs"), culprits...)
	}

	// Fig 7. Output.2 check equality
	modN := common.ModInt(round.EC().Params().N)
	𝛿 := round.temp.𝛿i
	Δ := round.temp.Δi
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		𝛿 = modN.Add(𝛿, round.temp.r3msg𝛿j[j])
		Δj := round.temp.r3msgΔj[j]
		var err error
		Δ, err = Δ.Add(Δj)
		if err != nil {
			return round.WrapError(errors.New("round4: failed to collect BigDelta"))
		}
	}

	if !crypto.ScalarBaseMult(round.EC(), 𝛿).Equals(Δ) {
		common.Logger.Errorf("part %v: verify BigDelta failed", round.PartyID())
		round.AbortingSigning = true
		round.setOK()
		common.Logger.Debugf("party %v, aborting and NewSignRound4AbortingMessage going out (broadcast)", round.PartyID())
		round.out <- NewSignRound4AbortingMessage(round.PartyID())
		return nil
	}
	// compute the multiplicative inverse thelta mod q
	𝛿Inverse := modN.Inverse(𝛿)
	BigR := round.temp.Γ.ScalarMult(𝛿Inverse)

	// Fig 8. Round 1. compute signature share
	r := BigR.X()
	𝜎i := modN.Add(modN.Mul(round.temp.ki, round.temp.m), modN.Mul(r, round.temp.𝜒i))

	common.Logger.Debugf("party %v, NewSignRound4Message going out (broadcast)", round.PartyID())
	r4msg := NewSignRound4Message(round.PartyID(), 𝜎i)
	round.out <- r4msg

	round.temp.BigR = BigR
	round.temp.Rx = r
	round.temp.SigmaShare = 𝜎i
	// retire unused variables

	round.temp.r3msgΔj = make([]*crypto.ECPoint, round.PartyCount())

	round.temp.r3msgProofLogstar = make([]*zkplogstar.ProofLogstar, round.PartyCount())

	return nil
}

func (round *sign4) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r4msg𝜎j {
		if round.ok[j] {
			common.Logger.Debugf("party %v, sign4 Update, j: %v already ok (𝜎)", round.PartyID(), j)
			continue
		}
		if msg == nil {
			common.Logger.Debugf("party %v, sign4 Update, no 𝜎 message received yet from j: %v (𝜎)", round.PartyID(), j)
			continue
		}
		round.ok[j] = true
		common.Logger.Debugf("party %v, sign4 Update, j: %v set to ok", round.PartyID(), j)
	}
	for j, aborting := range round.temp.r4msgAborting {
		if round.ok[j] {
			common.Logger.Debugf("party %v, sign4 Update, j: %v already ok (abort msg)", round.PartyID(), j)
			continue
		}
		if aborting {
			common.Logger.Debugf("party %v, sign4 Update, party j: %v sent abort msg", round.PartyID(), j)
			round.ok[j] = true
		} else {
			common.Logger.Debugf("party %v, sign4 Update, j: %v did not send abort msg yet", round.PartyID(), j)
		}
	}
	return true, nil
}

func (round *sign4) resetAborting() {
	for j := range round.temp.r4msgAborting {
		round.temp.r4msgAborting[j] = false
	}
}

func (round *sign4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound4AbortingMessage); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *sign4) NextRound() tss.Round {
	round.started = false

	for _, abortingMsg := range round.temp.r4msgAborting {
		if abortingMsg {
			round.AbortingSigning = true
			break
		}
	}
	if round.AbortingSigning {
		return &identificationPrep{round}
	}
	return &signout{round}
}
