// Copyright © 2020 Swingby

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

// This round is only invoked when there is an abort in round 7. This round ensures that all the messages in
// the last round have SignRound7Message_Abort content.
func (round *round7AbortPrep) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()
	Pi := round.PartyID()
	round.abortingT5 = true

	r6msg := NewSignRound6MessageAbort(Pi, &round.temp.r5AbortData)
	round.out <- r6msg
	return nil
}

func (round *round7AbortPrep) Update() (bool, *tss.Error) {
	return true, nil
}

func (round *round7AbortPrep) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound6Message).GetContent().(*SignRound6Message_Abort); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round7AbortPrep) NextRound() tss.Round {
	round.started = false
	return &round7{round, true}
}
