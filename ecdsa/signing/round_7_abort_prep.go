// Copyright © 2020 Swingby

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round7AbortPrep) InboundQueuesToConsume() []tss.QueueFunction {
	return nil
}

// This round is only invoked when there is an abort in round 7. This round ensures that all the messages in
// the last round have SignRound7Message_Abort content.
func (round *round7AbortPrep) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.ended = false
	Pi := round.PartyID()
	round.abortingT5 = true

	r6msg := NewSignRound6MessageAbort(Pi, &round.temp.r5AbortData)
	round.out <- r6msg
	return nil, nil
}

func (round *round7AbortPrep) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	round.ended = true
	return nil
}

func (round *round7AbortPrep) CanProcess(msg tss.ParsedMessage) bool {
	// No message expected
	return false
}

func (round *round7AbortPrep) NextRound() tss.Round {
	round.started = false
	return &round7{round, true}
}
