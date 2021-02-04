// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"github.com/Workiva/go-datastructures/queue"
)

type Round interface {
	Params() *Parameters
	Start() *Error
	Update() (bool, *Error)
	RoundNumber() int
	CanAccept(msg ParsedMessage) bool
	CanProceed() bool
	NextRound() Round
	WaitingFor() []*PartyID
	WrapError(err error, culprits ...*PartyID) *Error
}

type QueueFunction struct {
	Queue                     *queue.Queue
	Messages                  *[]ParsedMessage
	MessageProcessingFunction func(PreprocessingRound, *ParsedMessage, *PartyID, *GenericParameters) (*GenericParameters, *Error)
	Parallel                  bool
}

type PreprocessingRound interface {
	Round
	Preprocess() (*GenericParameters, *Error)
	Postprocess(*GenericParameters) *Error
	InboundQueuesToConsume() []QueueFunction
}
