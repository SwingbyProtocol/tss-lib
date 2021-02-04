// Copyright © 2020 Swingby

package signing

import (
	"errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *finalizationAbortPrep) InboundQueuesToConsume() []tss.QueueFunction {
	return []tss.QueueFunction{
		{round.temp.signRound7MessagesQII, &round.temp.signRound7Messages, ProcessFinalRoundPrep, true},
	}
}

func (round *finalizationAbortPrep) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	common.Logger.Debugf("party %v finalizationAbortPrep Preprocess", round.PartyID())
	round.number = 8
	round.started = true
	round.ended = false
	parameters := &tss.GenericParameters{Dictionary: make(map[string]interface{})}
	return parameters, nil
}

func ProcessFinalRoundPrep(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*finalizationAbortPrep)
	r7msg := (*msg).Content().(*SignRound7Message)
	common.Logger.Debugf("party %v Pj %v finalizationAbortPrep ProcessFinalRoundPrep", round.PartyID(), Pj)
	if r7msg.GetAbort() != nil {
		round.abortingT7 = true
		common.Logger.Debugf("party %v Pj %v finalizationAbortPrep ProcessFinalRoundPrep aborting!", round.PartyID(), Pj)
		otherR7msg := NewSignRound7MessageAbort(round.PartyID(), &round.temp.r7AbortData)
		round.out <- otherR7msg
		round.ended = true
	}
	return parameters, nil
}

func (round *finalizationAbortPrep) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	return nil
}

func (round *finalizationAbortPrep) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound7Message).GetContent().(*SignRound7Message_Abort); ok {
		return msg.IsBroadcast()
	}
	return false
}

//
func (round *finalizationAbortPrep) CanProceed() bool {
	c := round.started && round.ended
	common.Logger.Debugf("party %v, finalizationAbortPrep CanProceed? %v", round.PartyID(), c)
	return c
}

func (round *finalizationAbortPrep) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
