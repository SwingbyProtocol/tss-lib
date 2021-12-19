// Copyright © 2021 Swingby

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *identificationPrep) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	common.Logger.Debugf("party %v, identificationPrep Start", round.PartyID())
	round.started = true
	round.AbortingSigning = true
	round.resetOK()
	i := round.PartyID().Index
	round.ok[i] = true
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		r5msg := NewIdentificationPrepRound5Message(Pj, round.PartyID(), round.temp.𝛾i, round.temp.DeltaMtASij[j], round.temp.DeltaShareBetaNegs[j])
		round.out <- r5msg

	}

	return nil
}

func (round *identificationPrep) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*IdentificationPrepRound5Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *identificationPrep) NextRound() tss.Round {
	round.started = false
	return &identification6{round}
}

func (round *identificationPrep) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r5msg𝛾j {
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

func (round *identificationPrep) setOK() {
	for j := range round.ok {
		round.ok[j] = true
	}
}
