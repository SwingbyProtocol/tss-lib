// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Workiva/go-datastructures/queue"

	"github.com/binance-chain/tss-lib/common"
)

type Party interface {
	Start() *Error
	// The main entry point when updating a party's state from the wire.
	// isBroadcast should represent whether the message was received via a reliable broadcast
	UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool) (ok bool, err *Error)
	// You may use this entry point to update a party's state when running locally or in tests
	Update(msg ParsedMessage) (ok bool, err *Error)
	Running() bool
	WaitingFor() []*PartyID
	ValidateMessage(msg ParsedMessage) (bool, *Error)
	StoreMessage(msg ParsedMessage) (bool, *Error)
	FirstRound() Round
	WrapError(err error, culprits ...*PartyID) *Error
	PartyID() *PartyID
	String() string

	// Private lifecycle methods
	setRound(Round) *Error
	round() Round
	advance()
	Lock()
	Unlock()
}

type BaseParty struct {
	mtx        sync.Mutex
	rnd        Round
	FirstRound Round
}

func (p *BaseParty) Running() bool {
	return p.rnd != nil
}

func (p *BaseParty) WaitingFor() []*PartyID {
	p.Lock()
	defer p.Unlock()
	if p.rnd == nil {
		return []*PartyID{}
	}
	return p.rnd.WaitingFor()
}

func (p *BaseParty) WrapError(err error, culprits ...*PartyID) *Error {
	if p.rnd == nil {
		return NewError(err, "", -1, nil, culprits...)
	}
	return p.rnd.WrapError(err, culprits...)
}

// an implementation of ValidateMessage that is shared across the different types of parties (keygen, signing, dynamic groups)
func (p *BaseParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	if msg == nil || msg.Content() == nil {
		return false, p.WrapError(fmt.Errorf("received nil msg: %s", msg))
	}
	if msg.GetFrom() == nil || !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("received msg with an invalid sender: %s", msg))
	}
	if !msg.ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *BaseParty) String() string {
	if p.round() != nil {
		return fmt.Sprintf("round: %d", p.round().RoundNumber())
	}
	return "BaseParty (round nil)"
}

// -----
// Private lifecycle methods

func (p *BaseParty) setRound(round Round) *Error {
	if p.rnd != nil {
		return p.WrapError(errors.New("a round is already set on this party"))
	}
	p.rnd = round
	return nil
}

func (p *BaseParty) round() Round {
	return p.rnd
}

func (p *BaseParty) advance() {
	p.rnd = p.rnd.NextRound()
}

func (p *BaseParty) Lock() {
	p.mtx.Lock()
}

func (p *BaseParty) Unlock() {
	p.mtx.Unlock()
}

// ----- //

func BaseStart(p Party, task string) *Error {
	if p.PartyID() == nil || !p.PartyID().ValidateBasic() {
		return p.WrapError(fmt.Errorf("could not start. this party has an invalid PartyID: %+v", p.PartyID()))
	}
	if p.round() != nil {
		return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	round := p.FirstRound()
	if err := p.setRound(round); err != nil {
		return err
	}
	partyCount := len(p.round().Params().parties.IDs())
	for {
		p.Lock()
		if p.round() == nil {
			p.Unlock()
			break // The last round finished
		}
		pRound := p.round().(PreprocessingRound)
		parameters, errPP := pRound.Preprocess()
		if errPP != nil {
			return p.WrapError(errPP)
		}
		queuesAndFunctions := pRound.InboundQueuesToConsume()
		for _, queueAndFunction := range queuesAndFunctions {
			elementsProcessed := 0
			for elementsProcessed < partyCount-1 {
				msgs, errQ := queueAndFunction.Queue.Get(int64(partyCount))
				if errQ != nil {
					return p.WrapError(errQ)
				}
				if e := processInParallel(msgs, pRound, queueAndFunction.MessageProcessingFunction, parameters,
					&elementsProcessed); e != nil {
					return e
				}
			}
			queueAndFunction.Queue.Dispose()
		}
		common.Logger.Debugf("party %s: %s round %d postproc starting", p.round().Params().PartyID(),
			task, p.round().RoundNumber())
		errO := pRound.Postprocess(parameters)
		if errO != nil {
			return p.WrapError(errO)
		}
		if p.round().CanProceed() {
			p.advance()
		}
		p.Unlock()
	}
	defer func() {
		common.Logger.Debugf("party %s: %s finished", p, task)
	}()
	return nil
}

func processInParallel(msgs []interface{}, pRound PreprocessingRound,
	messageProcessingFunction func(PreprocessingRound, *ParsedMessage, *PartyID, *GenericParameters) (*GenericParameters, *Error),
	parameters *GenericParameters, elementsProcessed *int) *Error {
	queueClone := new(queue.Queue)
	if err := queueClone.Put(msgs); err != nil {
		return pRound.WrapError(err)
	}
	f := func(msgs_ interface{}) {
		msgs2_ := msgs_.([]interface{})
		for _, msg_ := range msgs2_ {
			msg2 := msg_.(*MessageImpl)
			msgO := NewMessage(msg2.MessageRouting, msg2.content, msg2.wire)
			msg := &msgO

			toP := (*msg).GetTo()
			var errP *Error
			if toP == nil { // broadcast
				parameters, errP = messageProcessingFunction(pRound, msg, (*msg).GetFrom(), parameters)
				if errP != nil {
					common.Logger.Errorf("error msg from %v, msg: %v, error %v",
						msg2.From, FormatParsedMessage(*msg), errP)
					return // TODO error channel
				}
			} else { // P2P
				parameters, errP = messageProcessingFunction(pRound, msg, (*msg).GetTo()[0], parameters)
			}
			if errP != nil {
				common.Logger.Errorf("error %v", errP)
				return // TODO error channel
			}
			*elementsProcessed++
		}
	}
	queue.ExecuteInParallel(queueClone, f)
	return nil
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg ParsedMessage) (ok bool, err *Error) {

	// fast-fail on an invalid message; do not lock the mutex yet
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}

	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return false, err
	}
	return true, nil
}
