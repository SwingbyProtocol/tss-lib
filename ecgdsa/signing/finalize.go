// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/schnorr"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 8
	round.started = true
	round.resetOK()
	modN := common.ModInt(tss.EC().Params().N)

	sumS := round.temp.si
	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r7msg := round.temp.signRound7Messages[j].Content().(*SignRound7Message)
		sumS = modN.Add(sumS, r7msg.UnmarshalS())
	}
	// save the signature for final output
	round.data.Signature = append(round.temp.r.Bytes(), sumS.Bytes()...)
	round.data.R = round.temp.r.Bytes()
	round.data.S = sumS.Bytes()
	round.data.M = round.temp.m.Bytes()

	pk := schnorr.PublicKey{
		X: round.key.ECGDSAPub.X,
		Y: round.key.ECGDSAPub.Y,
	}

	ok := pk.Verify(round.temp.m.Bytes(), round.temp.r, sumS)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}
	round.end <- round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
