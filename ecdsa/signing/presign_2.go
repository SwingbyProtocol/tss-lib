// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"
	"sync"

	"github.com/binance-chain/tss-lib/crypto"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *presign2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Round 2.1 verify received proof enc
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			
			r1msg := round.temp.presignRound1Messages[j].Content().(*PreSignRound1Message)
			Kj := r1msg.UnmarshalK()
			proof, err := r1msg.UnmarshalEncProof()
			if err != nil {
				errChs <- round.WrapError(errors.New("round2: proofenc verity failed"), Pj)
				return
			}
			ok := proof.Verify(round.EC(), round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, Kj)
			if !ok {
				errChs <- round.WrapError(errors.New("round2: proofenc verify failed"), Pj)
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
		return round.WrapError(errors.New("round2: proofenc verify failed"), culprits...)
	}

	// Fig 7. Round 2.2 compute MtA and generate proofs
	BigGammaShare := crypto.ScalarBaseMult(round.Params().EC(), round.temp.GammaShare)
	g := crypto.ScalarBaseMult(round.EC(), big.NewInt(1)) // used in prooflogstar
	errChs = make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		r1msg := round.temp.presignRound1Messages[j].Content().(*PreSignRound1Message)
		Kj := r1msg.UnmarshalK()

		DeltaOut := make(chan *MtAOut, 1)
		ChiOut := make(chan *MtAOut, 1)
		ProofOut := make(chan *zkplogstar.ProofLogstar, 1)
		wgj := sync.WaitGroup{}

		wgj.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wgj.Done()
			DeltaMtA, err := NewMtA(round.EC(), Kj, round.temp.GammaShare, BigGammaShare, round.key.PaillierPKs[j], &round.key.PaillierSK.PublicKey, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
			if err != nil {
				errChs <- round.WrapError(errors.New("MtADelta failed"))
				return
			}
			DeltaOut <- DeltaMtA
		}(j, Pj)

		wgj.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wgj.Done()
			ChiMtA, err := NewMtA(round.EC(), Kj, round.temp.w, round.temp.BigWs[i], round.key.PaillierPKs[j], &round.key.PaillierSK.PublicKey, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
			if err != nil {
				errChs <- round.WrapError(errors.New("MtAChi failed"))
				return
			}
			ChiOut <- ChiMtA
		}(j, Pj)

		wgj.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wgj.Done()
			ProofLogstar, err := zkplogstar.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.G, BigGammaShare, g ,round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.GammaShare, round.temp.GNonce)
			if err != nil {
				errChs <- round.WrapError(errors.New("prooflogstar failed"))
				return
			}
			ProofOut <- ProofLogstar
		}(j, Pj)
		
		wgj.Wait()
		DeltaMtA := <-DeltaOut
		ChiMtA := <-ChiOut
		ProofLogstar := <- ProofOut

		r2msg := NewPreSignRound2Message(Pj, round.PartyID(), BigGammaShare, DeltaMtA.Dji, DeltaMtA.Fji, ChiMtA.Dji, ChiMtA.Fji, DeltaMtA.Proofji, ChiMtA.Proofji, ProofLogstar)
		round.out <- r2msg

		round.temp.DeltaShareBetas[j] = DeltaMtA.Beta
		round.temp.ChiShareBetas[j] = ChiMtA.Beta
	}
	close(errChs)
	for err := range errChs {
		return err
	}

	round.temp.BigGammaShare = BigGammaShare
	// retire unused variables
	round.temp.G = nil
	round.temp.GNonce = nil
	return nil
}

func (round *presign2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.presignRound2Messages {
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

func (round *presign2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*PreSignRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *presign2) NextRound() tss.Round {
	round.started = false
	return &presign3{round}
}