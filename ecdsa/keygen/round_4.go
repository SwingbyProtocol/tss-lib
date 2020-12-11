// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"

	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	// 1-3. (concurrent)
	// r3 messages are assumed to be available and != nil in this function
	r3msgs := round.temp.kgRound3Messages
	abortr3msgs := make([]tss.ParsedMessage, 0)
	for _, m := range r3msgs {
		if m.Type() == "KGRound3MessageAbortMode" {
			abortr3msgs = append(abortr3msgs, m)
		}
	}
	i := round.PartyID().Index
	Ps := round.Parties().IDs()
	if len(abortr3msgs) > 0 {
		return round.startInAbortMode(i, Ps, abortr3msgs)
	} else {
		PIDs := Ps.Keys()
		ecdsaPub := round.save.ECDSAPub
		return round.startNormal(i, Ps, PIDs, ecdsaPub, r3msgs)
	}
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
