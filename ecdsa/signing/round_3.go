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

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
    if round.started {
        return round.WrapError(errors.New("round already started"))
    }
    round.number = 3
    round.started = true
    round.resetOK()

    i := round.PartyID().Index
    round.ok[i] = true

    // Fig 7. Round 3.1 verify proofs received and decrypt alpha share of MtA output
    g := crypto.ScalarBaseMult(round.EC(), big.NewInt(1)) // used in prooflogstar
    errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
    wg := sync.WaitGroup{}
    for j, Pj := range round.Parties().IDs() {
        if j == i {
            continue
        }
        r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
        BigGammaSharej, err := r2msg.UnmarshalBigGammaShare(round.EC())
        if err != nil {
            errChs <- round.WrapError(errors.New("round3: received broken message"))
            break
        }

        wg.Add(1)
        go func(j int, Pj *tss.PartyID) {
            defer wg.Done()

            DeltaD := r2msg.UnmarshalDjiDelta()
            DeltaF := r2msg.UnmarshalFjiDelta()
            proofAffgDelta, err := r2msg.UnmarshalAffgProofDelta(round.EC())
            if err != nil {
                errChs <- round.WrapError(errors.New("failed to unmarshal affg_delta in r2msg"))
                return
            }
            ok := proofAffgDelta.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, DeltaD, DeltaF, BigGammaSharej)
            if !ok {
                errChs <- round.WrapError(errors.New("failed to verify affg delta"))
                return
            }
            round.temp.DeltaShareAlphas[j], err = round.key.PaillierSK.Decrypt(DeltaD)
            if err != nil {
                errChs <- round.WrapError(errors.New("failed to do mta"))
                return
            }
        }(j, Pj)

        wg.Add(1)
        go func(j int, Pj *tss.PartyID) {
            defer wg.Done()

            ChiD := r2msg.UnmarshalDjiChi()
            ChiF := r2msg.UnmarshalFjiChi()
            proofAffgChi, err := r2msg.UnmarshalAffgProofChi(round.EC())
            if err != nil {
                errChs <- round.WrapError(errors.New("failed to unmarshal affg chi from r2msg"))
                return
            }
            ok := proofAffgChi.Verify(round.EC(), &round.key.PaillierSK.PublicKey, round.key.PaillierPKs[j], round.key.NTildei, round.key.H1i, round.key.H2i, round.temp.K, ChiD, ChiF, round.temp.BigWs[j])
            if !ok {
                errChs <- round.WrapError(errors.New("failed to verify affg chi"))
                return
            }
            round.temp.ChiShareAlphas[j], err = round.key.PaillierSK.Decrypt(ChiD)
            if err != nil {
                errChs <- round.WrapError(errors.New("failed to do mta"))
                return
            }
        }(j, Pj)

        wg.Add(1)
        go func(j int, Pj *tss.PartyID) {
            defer wg.Done()

            proofLogstar, err := r2msg.UnmarshalLogstarProof(round.EC())
            if err != nil {
                errChs <- round.WrapError(errors.New("failed to verify logstar"))
                return
            }
            r1msg := round.temp.signRound1Messages[j].Content().(*SignRound1Message)
            Gj := r1msg.UnmarshalG()
            ok := proofLogstar.Verify(round.EC(), round.key.PaillierPKs[j], Gj, BigGammaSharej, g, round.key.NTildei, round.key.H1i, round.key.H2i)
            if !ok {
                errChs <- round.WrapError(errors.New("failed to verify logstar"))
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
        return round.WrapError(errors.New("round3: failed to verify proofs"), culprits...)
    }

    // Fig 7. Round 3.2 accumulate results from MtA
    BigGamma := round.temp.BigGammaShare
    for j := range round.Parties().IDs() {
        if j == i {
            continue
        }
        r2msg := round.temp.signRound2Messages[j].Content().(*SignRound2Message)
        BigGammaShare, err := r2msg.UnmarshalBigGammaShare(round.EC())
        if err != nil {
            return round.WrapError(errors.New("round3: failed to collect BigGamma"))
        }
        BigGamma, err = BigGamma.Add(BigGammaShare)
        if err != nil {
            return round.WrapError(errors.New("round3: failed to collect BigGamma"))
        }
    }
    BigDeltaShare := BigGamma.ScalarMult(round.temp.KShare)

    modN := common.ModInt(round.EC().Params().N)
    DeltaShare := modN.Mul(round.temp.KShare, round.temp.GammaShare)
    ChiShare := modN.Mul(round.temp.KShare, round.temp.w)
    for j := range round.Parties().IDs() {
        if j == i {
            continue
        }
        DeltaShare = modN.Add(DeltaShare, round.temp.DeltaShareAlphas[j])
        DeltaShare = modN.Add(DeltaShare, round.temp.DeltaShareBetas[j])

        ChiShare = modN.Add(ChiShare, round.temp.ChiShareAlphas[j])
        ChiShare = modN.Add(ChiShare, round.temp.ChiShareBetas[j])
    }

    errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
    wg = sync.WaitGroup{}
    for j, Pj := range round.Parties().IDs() {
        if j == i {
            continue
        }
        ProofOut := make(chan *zkplogstar.ProofLogstar, 1)
        wg.Add(1)
        go func(j int, Pj *tss.PartyID) {
            defer wg.Done()
            ProofLogstar, err := zkplogstar.NewProof(round.EC(), &round.key.PaillierSK.PublicKey, round.temp.K, BigDeltaShare, BigGamma, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j], round.temp.KShare, round.temp.KNonce)
            if err != nil {
                errChs <- round.WrapError(errors.New("proof generation failed"))
            }
            ProofOut <- ProofLogstar
        }(j, Pj)

        ProofLogstar := <-ProofOut
        r3msg := NewSignRound3Message(Pj, round.PartyID(), DeltaShare, BigDeltaShare, ProofLogstar)
        round.out <- r3msg
    }
    wg.Wait()
    close(errChs)
    for err := range errChs {
        return err
    }

    round.temp.DeltaShare = DeltaShare
    round.temp.ChiShare = ChiShare
    round.temp.BigDeltaShare = BigDeltaShare
    round.temp.BigGamma = BigGamma
    // retire unused variables
    round.temp.w = nil
    round.temp.BigWs = nil
    round.temp.GammaShare = nil
    round.temp.BigGammaShare = nil
    round.temp.K = nil
    round.temp.KNonce = nil
    round.temp.DeltaShareBetas = nil
    round.temp.ChiShareBetas = nil
    round.temp.DeltaShareAlphas = nil
    round.temp.ChiShareAlphas = nil

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
        return !msg.IsBroadcast()
    }
    return false
}

func (round *round3) NextRound() tss.Round {
    round.started = false
    return &round4{round}
}
