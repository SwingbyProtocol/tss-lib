// Copyright © 2020 Swingby

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

// This round is only invoked when there is an abort in round 7. This round ensures that all the messages in
// the last round have SignRound7Message_Abort content.
func (round *abortPrep) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.resetOK()
	Pi := round.PartyID()
	i := Pi.Index
	round.abortingT7 = true
	r7msg := NewSignRound7MessageAbort(Pi, &round.temp.r7AbortData)
	round.temp.signRound7Messages[i] = r7msg
	round.out <- r7msg
	return nil
}

func (round *abortPrep) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound7Messages {
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

func (round *abortPrep) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound7Message).GetContent().(*SignRound7Message_Abort); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *abortPrep) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
