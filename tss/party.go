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
	"time"

	"github.com/Workiva/go-datastructures/queue"
	"github.com/hashicorp/go-multierror"

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

type QueuingParty interface {
	StoreMessageInQueues(msg ParsedMessage) (bool, *Error)
	ValidateAndStoreInQueues(msg ParsedMessage) (ok bool, err *Error)
	IsMessageAlreadyStored(msg ParsedMessage) bool
}

type BaseParty struct {
	mtx        sync.Mutex
	rnd        Round
	FirstRound Round
}

const QueuePollTimeoutInSeconds = 180
const QueueWaitTimeInMilliseconds = 100

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

func BaseStart(p Party, task string, prepare ...func(Round) *Error) *Error {
	p.Lock()
	defer p.Unlock()
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
	if 1 < len(prepare) {
		return p.WrapError(errors.New("too many prepare functions given to Start(); 1 allowed"))
	}
	if len(prepare) == 1 {
		if err := prepare[0](round); err != nil {
			return err
		}
	}
	common.Logger.Infof("party %s: %s round %d starting", p.round().Params().PartyID(), task, 1)
	defer func() {
		common.Logger.Debugf("party %s: %s round %d finished", p.round().Params().PartyID(), task, 1)
	}()
	return p.round().Start()
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg ParsedMessage, task string) (ok bool, err *Error) {
	// fast-fail on an invalid message; do not lock the mutex yet
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	// lock the mutex. need this mtx unlock hook; L108 is recursive so cannot use defer
	r := func(ok bool, err *Error) (bool, *Error) {
		p.Unlock()
		return ok, err
	}
	p.Lock() // data is written to P state below
	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	if p.round() != nil {
		common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.round().RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.round() != nil {
		common.Logger.Debugf("party %s: %s round %d update", p.round().Params().PartyID(), task, p.round().RoundNumber())
		if _, err := p.round().Update(); err != nil {
			return r(false, err)
		}
		if p.round().CanProceed() {
			if p.advance(); p.round() != nil {
				if err := p.round().Start(); err != nil {
					return r(false, err)
				}
				rndNum := p.round().RoundNumber()
				common.Logger.Infof("party %s: %s round %d started", p.round().Params().PartyID(), task, rndNum)
			} else {
				// finished! the round implementation will have sent the data through the `end` channel.
				common.Logger.Infof("party %s: %s finished!", p.PartyID(), task)
			}
			p.Unlock()                      // recursive so can't defer after return
			return BaseUpdate(p, msg, task) // re-run round update or finish)
		}
		return r(true, nil)
	}
	return r(true, nil)
}

// ----- //

func StartAndProcessQueues(p Party, task string) *Error {
	if p.PartyID() == nil || !p.PartyID().ValidateBasic() {
		return p.WrapError(fmt.Errorf("could not start. this party has an invalid PartyID: %+v", p.PartyID()))
	}
	if p.round() != nil {
		return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	round := p.FirstRound()
	Pi := p.PartyID()
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
		rndNum := p.round().RoundNumber()
		p.Unlock()
		common.Logger.Infof("party %s: %s round %d started", Pi, task, rndNum)
		if errPP != nil {
			common.Logger.Error(errPP)
			return p.WrapError(errPP)
		}
		queuesAndFunctions := pRound.InboundQueuesToConsume()
		for _, queueAndFunction := range queuesAndFunctions {
			elementsProcessed := 0
			for elementsProcessed < partyCount-1 {
				var number int64
				if queueAndFunction.Parallel {
					number = int64(partyCount - elementsProcessed - 1)
				} else {
					number = 1
				}
				// common.Logger.Debugf("party %v will read &q %p", Pi, queueAndFunction.Queue)
				msgFromIndices, errQ := queueAndFunction.Queue.Poll(number, QueuePollTimeoutInSeconds*time.Second)
				elementsProcessed = elementsProcessed + len(msgFromIndices)
				if errQ != nil {
					common.Logger.Errorf("error: %v", errQ)
					return p.WrapError(errQ)
				}
				parsedMessages := make([]ParsedMessage, len(msgFromIndices))
				set := make(map[int]interface{}, len(msgFromIndices))
				p.Lock()
				for a, index_ := range msgFromIndices {
					fromPartyIndex := index_.(int)
					set[fromPartyIndex] = fromPartyIndex
					m := (*queueAndFunction.Messages)[fromPartyIndex]
					parsedMessages[a] = m
				}
				if len(set) != len(parsedMessages) {
					err := fmt.Errorf("party %v: there are repeated party messages or messages to self", p.PartyID())
					common.Logger.Error(err)
					return p.WrapError(err)
				}
				p.Unlock()
				if e := processInParallel(parsedMessages, pRound, queueAndFunction.MessageProcessingFunction, parameters); e != nil {
					return e
				}
			}
			// queueAndFunction.Queue.Dispose()
		}
		if errO := pRound.Postprocess(parameters); errO != nil {
			return errO
		}
		p.Lock()
		for {
			if p.round().CanProceed() {
				// common.Logger.Debugf("party %v is advancing", Pi)
				p.advance()
				break
			} else {
				p.Unlock()
				// common.Logger.Debugf("party %v cannot proceed yet and will sleep", Pi)
				time.Sleep(QueueWaitTimeInMilliseconds * time.Millisecond)
				p.Lock()
			}
		}
		p.Unlock()
	}
	defer func() {
		common.Logger.Debugf("party %s: %s finished", Pi, task)
	}()
	return nil
}

func processInParallel(msgs []ParsedMessage, pRound PreprocessingRound,
	messageProcessingFunction func(PreprocessingRound, *ParsedMessage, *PartyID, *GenericParameters, sync.RWMutex) (*GenericParameters, *Error),
	parameters *GenericParameters) *Error {
	queueClone := new(queue.Queue)
	if err := queueClone.Put(msgs); err != nil {
		return pRound.WrapError(err)
	}
	var multiErr error
	errCh := make(chan *Error, queueClone.Len())
	mutex := sync.RWMutex{}
	f := func(msgs_ interface{}) {
		msgs2_ := msgs_.([]ParsedMessage)
		for _, msg := range msgs2_ {
			if !pRound.CanProcess(msg) {
				errorMessage := fmt.Sprintf("invalid message %v from party %v", msg, msg.GetFrom())
				e := errors.New(errorMessage)
				common.Logger.Warnf(errorMessage)
				errCh <- pRound.WrapError(e, []*PartyID{msg.GetFrom()}...)
				break
			}
			var errP *Error
			parameters, errP = messageProcessingFunction(pRound, &msg, msg.GetFrom(), parameters, mutex)
			if errP != nil {
				errCh <- errP
				break
			}
		}
	}
	queue.ExecuteInParallel(queueClone, f)
	close(errCh)
	culprits := make([]*PartyID, 0, queueClone.Len())
	if len(errCh) > 0 {
		for err := range errCh {
			culprits = append(culprits, err.Culprits()...)
			multiErr = multierror.Append(multiErr, err.Cause())
		}
		return pRound.WrapError(multiErr, culprits...)
	}
	return nil
}

func BaseValidateAndStore(toParty Party, msg ParsedMessage) (ok bool, err *Error) {
	// fast-fail on an invalid message; do not lock the mutex yet
	if _, err := toParty.ValidateMessage(msg); err != nil {
		return false, err
	}
	toParty.Lock()
	defer toParty.Unlock()
	common.Logger.Debugf("party %v msg %v BaseValidateAndStore", toParty, msg)
	qp := toParty.(QueuingParty)
	isRepeated := qp.IsMessageAlreadyStored(msg)
	if ok, err := toParty.StoreMessage(msg); err != nil || !ok {
		return false, err
	}
	if isRepeated {
		common.Logger.Warnf("ignoring repeated message %v from party %v to %v", msg, msg.GetFrom(), toParty)
	} else if ok, err := qp.StoreMessageInQueues(msg); err != nil || !ok {
		return false, err
	}
	return true, nil
}
