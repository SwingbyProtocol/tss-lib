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
	round.setOK()
	return nil
}

func (round *identificationPrep) NextRound() tss.Round {
	round.started = false
	return &identification6{round}
}

func (round *identificationPrep) Update() (bool, *tss.Error) {
	return true, nil
}

func (round *identificationPrep) setOK() {
	for j := range round.ok {
		round.ok[j] = true
	}
}