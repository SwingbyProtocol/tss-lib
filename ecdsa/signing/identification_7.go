// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"
	sync "sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func newRound7(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &identification7{&identification6{&identificationPrep{&sign4{&presign3{&presign2{&presign1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 3}}}}, false}}}}
}

func (round *identification7) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	// Fig 7. Output.2
	errChs := make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			
			proofMul := round.temp.r6msgProofMul[j]
			ok := proofMul.Verify(round.EC(), round.key.PaillierPKs[j], round.temp.r1msgK[j], round.temp.r1msgG[j], round.temp.r6msgH[j])
			if !ok {
				errChs <- round.WrapError(errors.New("round7: proofmul verify failed"), Pj)
				return
			}

			proofDec := round.temp.r6msgProofDec[j]

			ok = proofDec.Verify(round.EC(), round.key.PaillierPKs[j], round.temp.r6msgDeltaShareEnc[j], round.temp.r3msg𝛿j[j], round.key.NTildei, round.key.H1i, round.key.H2i)
			if !ok {
				common.Logger.Debugf("party: %v r7 Verify FAIL j: %v, PK: %v, DeltaShareEnc(C): %v, 𝛿j(x): %v, NTildei(NCap): %v, " +
					"H1j(s): %v, H2j(t): %v",
					round.PartyID(), j, common.FormatBigInt(round.key.PaillierPKs[j].N),
					common.FormatBigInt(round.temp.r6msgDeltaShareEnc[j]),
					common.FormatBigInt(round.temp.r3msg𝛿j[j]),
					common.FormatBigInt(round.key.NTildei), common.FormatBigInt(round.key.H1i), common.FormatBigInt(round.key.H2i))
				errChs <- round.WrapError(errors.New("round7: proofdec verify failed"), Pj)
				return
			} else { // TODO
				common.Logger.Debugf("party: %v r7 Verify OK j: %v, PK: %v, DeltaShareEnc(C): %v, 𝛿j(x): %v, NTildei(NCap): %v, " +
					"H1j(s): %v, H2j(t): %v",
					round.PartyID(), j, common.FormatBigInt(round.key.PaillierPKs[j].N),
					common.FormatBigInt(round.temp.r6msgDeltaShareEnc[j]),
					common.FormatBigInt(round.temp.r3msg𝛿j[j]),
					common.FormatBigInt(round.key.NTildei), common.FormatBigInt(round.key.H1i), common.FormatBigInt(round.key.H2i))
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
		return round.WrapError(errors.New("round7: identification verify failed"), culprits...)
	}

	// retire unused variables
	round.temp.r1msgG = make([]*big.Int, round.PartyCount())
	round.temp.r1msgK = make([]*big.Int, round.PartyCount())
	round.temp.r3msg𝛿j = make([]*big.Int, round.PartyCount())
	return nil
}

func (round *identification7) Update() (bool, *tss.Error) {
	return true, nil
}

func (round *identification7) CanAccept(msg tss.ParsedMessage) bool {
	return true
}

func (round *identification7) NextRound() tss.Round {
	round.started = false
	return nil
}
