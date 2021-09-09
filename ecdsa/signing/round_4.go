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
    "github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
    if round.started {
        return round.WrapError(errors.New("round already started"))
    }
    round.number = 4
    round.started = true
    round.resetOK()

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

            r1msg := round.temp.signRound1Messages[j].Content().(*SignRound1Message)
            r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
            Kj := r1msg.UnmarshalK()
            BigDeltaSharej, err := r3msg.UnmarshalBigDeltaShare(round.EC())
			if err != nil {
                errChs <- round.WrapError(errors.New("proof verify failed"), Pj)
                return
            }
            proofLogstar, err := r3msg.UnmarshalProofLogstar(round.EC())
            if err != nil {
                errChs <- round.WrapError(errors.New("proof verify failed"), Pj)
                return
            }

            ok := proofLogstar.Verify(round.EC(), round.key.PaillierPKs[j], Kj, BigDeltaSharej, round.temp.BigGamma, round.key.NTildei, round.key.H1i, round.key.H2i)
            if !ok {
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
    Delta := round.temp.DeltaShare
    BigDelta := round.temp.BigDeltaShare
    for j := range round.Parties().IDs() {
        if j == i {
            continue
        }
        // verify zklog received
        r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)

        Delta = modN.Add(Delta, r3msg.UnmarshalDeltaShare())
		BigDeltaShare, err := r3msg.UnmarshalBigDeltaShare(round.EC())
		if err != nil {
			return round.WrapError(errors.New("round4: failed to collect BigDelta"))
		}
        BigDelta, err = BigDelta.Add(BigDeltaShare)
		if err != nil {
			return round.WrapError(errors.New("round4: failed to collect BigDelta"))
		}
    }

    DeltaPoint := crypto.ScalarBaseMult(round.EC(), Delta)
    if !DeltaPoint.Equals(BigDelta) {
        return round.WrapError(errors.New("verify BigDelta failed"))
    }
    // compute the multiplicative inverse thelta mod q
    deltaInverse := modN.ModInverse(Delta)
    BigR := round.temp.BigGamma.ScalarMult(deltaInverse)
    
    // Fig 8. Round 1. compute signature share
    Rx := BigR.X()
    SigmaShare := modN.Add(modN.Mul(round.temp.KShare, round.temp.m), modN.Mul(Rx, round.temp.ChiShare))

    r4msg := NewSignRound4Message(round.PartyID(), SigmaShare)
    round.temp.signRound4Messages[round.PartyID().Index] = r4msg
    round.out <- r4msg

    round.temp.BigR = BigR
    round.temp.Rx = Rx
    round.temp.SigmaShare = SigmaShare
    
    return nil
}

func (round *round4) Update() (bool, *tss.Error) {
    for j, msg := range round.temp.signRound4Messages {
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

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
    if _, ok := msg.Content().(*SignRound4Message); ok {
        return msg.IsBroadcast()
    }
    return false
}

func (round *round4) NextRound() tss.Round {
    round.started = false
    return &finalization{round}
}
