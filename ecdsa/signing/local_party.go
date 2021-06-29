// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"fmt"
	"math/big"

	"github.com/Workiva/go-datastructures/queue"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ tss.QueuingParty = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data SignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- *SignatureData
	}

	localMessageStore struct {
		signRound1Message1s,
		signRound1Message2s,
		signRound2Messages,
		signRound3Messages,
		signRound4Messages,
		signRound5Messages,
		signRound6Messages,
		signRound7Messages []tss.ParsedMessage

		signRound1Message1sQ,
		signRound1Message1sQII,
		signRound1Message1sQIII,
		signRound1Message2sQ,
		signRound2MessagesQ,
		signRound3MessagesQ,
		signRound3MessagesQII,
		signRound4MessagesQ,
		signRound5MessagesQ,
		signRound6MessagesQ,
		signRound7MessagesQ,
		signRound7MessagesQII *queue.Queue
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		m,
		wI,
		cAKI,
		rAKI,
		deltaI,
		sigmaI,
		keyDerivationDelta,
		gammaI *big.Int
		c1Is     []*big.Int
		bigWs    []*crypto.ECPoint
		gammaIG  *crypto.ECPoint
		deCommit cmt.HashDeCommitment

		// round 2
		betas, // return value of Bob_mid
		c1JIs,
		c2JIs,
		vJIs []*big.Int // return value of Bob_mid_wc
		pI1JIs []*mta.ProofBob
		pI2JIs []*mta.ProofBobWC

		// round 3
		lI *big.Int

		// round 5
		bigGammaJs  []*crypto.ECPoint
		r5AbortData SignRound6Message_AbortData

		// round 6
		SignatureData_OneRoundData
		bigSI *crypto.ECPoint

		// round 7
		sI *big.Int
		rI,
		TI *crypto.ECPoint
		r7AbortData SignRound7Message_AbortData
	}
)

// Constructs a new ECDSA signing party. Note: msg may be left nil for one-round signing mode to only do the pre-processing steps.
func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- *SignatureData,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      SignatureData{},
		out:       out,
		end:       end,
	}
	// msgs init

	p.temp.signRound1Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound1Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound4Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound5Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound6Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound7Messages = make([]tss.ParsedMessage, partyCount)

	p.temp.signRound1Message1sQ = new(queue.Queue)
	p.temp.signRound1Message1sQII = new(queue.Queue)
	p.temp.signRound1Message1sQIII = new(queue.Queue)
	p.temp.signRound1Message2sQ = new(queue.Queue)
	p.temp.signRound2MessagesQ = new(queue.Queue)
	p.temp.signRound3MessagesQ = new(queue.Queue)
	p.temp.signRound3MessagesQII = new(queue.Queue)
	p.temp.signRound4MessagesQ = new(queue.Queue)
	p.temp.signRound5MessagesQ = new(queue.Queue)
	p.temp.signRound6MessagesQ = new(queue.Queue)
	p.temp.signRound7MessagesQ = new(queue.Queue)
	p.temp.signRound7MessagesQII = new(queue.Queue)

	// message channels

	// temp data init
	p.temp.keyDerivationDelta = keyDerivationDelta
	p.temp.m = msg
	p.temp.c1Is = make([]*big.Int, partyCount)
	p.temp.bigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.betas = make([]*big.Int, partyCount)
	p.temp.c1JIs = make([]*big.Int, partyCount)
	p.temp.c2JIs = make([]*big.Int, partyCount)
	p.temp.pI1JIs = make([]*mta.ProofBob, partyCount)
	p.temp.pI2JIs = make([]*mta.ProofBobWC, partyCount)
	p.temp.vJIs = make([]*big.Int, partyCount)
	p.temp.bigGammaJs = make([]*crypto.ECPoint, partyCount)
	p.temp.r5AbortData.AlphaIJ = make([][]byte, partyCount)
	p.temp.r5AbortData.BetaJI = make([][]byte, partyCount)
	return p
}

// Constructs a new ECDSA signing party for one-round signing. The final SignatureData struct will be a partial struct containing only the data for a final signing round (see the readme).
func NewLocalPartyWithOneRoundSign(
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- *SignatureData,
) tss.Party {
	return NewLocalParty(nil, params, key, keyDerivationDelta, out, end)
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.StartAndProcessQueues(p, TaskName)
}

func (p *LocalParty) ValidateAndStoreInQueues(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseValidateAndStore(p, msg)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.ValidateAndStoreInQueues(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	if p.PartyID().Index == msg.GetFrom().Index {
		common.Logger.Warnf("party %v should not send message to self", msg.GetFrom())
		return true, nil
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *SignRound1Message1:
		p.temp.signRound1Message1s[fromPIdx] = msg
	case *SignRound1Message2:
		p.temp.signRound1Message2s[fromPIdx] = msg
	case *SignRound2Message:
		p.temp.signRound2Messages[fromPIdx] = msg
	case *SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = msg
	case *SignRound4Message:
		p.temp.signRound4Messages[fromPIdx] = msg
	case *SignRound5Message:
		p.temp.signRound5Messages[fromPIdx] = msg
	case *SignRound6Message:
		p.temp.signRound6Messages[fromPIdx] = msg
	case *SignRound7Message:
		p.temp.signRound7Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) StoreMessageInQueues(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index
	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *SignRound1Message1:
		if err := p.temp.signRound1Message1sQ.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
		if err := p.temp.signRound1Message1sQII.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
		if err := p.temp.signRound1Message1sQIII.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
	case *SignRound1Message2:
		if err := p.temp.signRound1Message2sQ.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
	case *SignRound2Message:
		if err := p.temp.signRound2MessagesQ.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
	case *SignRound3Message:
		if err := p.temp.signRound3MessagesQ.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
		if err := p.temp.signRound3MessagesQII.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
	case *SignRound4Message:
		if err := p.temp.signRound4MessagesQ.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
	case *SignRound5Message:
		if err := p.temp.signRound5MessagesQ.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
	case *SignRound6Message:
		if err := p.temp.signRound6MessagesQ.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
	case *SignRound7Message:
		if err := p.temp.signRound7MessagesQ.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
		if err := p.temp.signRound7MessagesQII.Put(fromPIdx); err != nil {
			return false, p.WrapError(err)
		}
	default: // unrecognised message, just ignore!
		common.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) IsMessageAlreadyStored(msg tss.ParsedMessage) bool {
	fromPIdx := msg.GetFrom().Index
	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *SignRound1Message1:
		return p.temp.signRound1Message1s[fromPIdx] != nil
	case *SignRound1Message2:
		return p.temp.signRound1Message2s[fromPIdx] != nil
	case *SignRound2Message:
		return p.temp.signRound2Messages[fromPIdx] != nil
	case *SignRound3Message:
		return p.temp.signRound3Messages[fromPIdx] != nil
	case *SignRound4Message:
		return p.temp.signRound4Messages[fromPIdx] != nil
	case *SignRound5Message:
		return p.temp.signRound5Messages[fromPIdx] != nil
	case *SignRound6Message:
		return p.temp.signRound6Messages[fromPIdx] != nil
	case *SignRound7Message:
		return p.temp.signRound7Messages[fromPIdx] != nil
	default: // unrecognised message, just ignore!
		return false
	}
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
