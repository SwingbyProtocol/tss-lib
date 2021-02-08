// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) InboundQueuesToConsume() []tss.QueueFunction {
	return nil
}

func (round *round4) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.ended = false
	round.resetOK()

	Pi := round.PartyID()
	// i := Pi.Index

	r4msg := NewSignRound4Message(Pi, round.temp.deCommit)
	round.out <- r4msg
	round.ended = true
	return nil, nil
}

func (round *round4) Postprocess(*tss.GenericParameters) *tss.Error {
	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) CanProceed() bool {
	return round.started
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
