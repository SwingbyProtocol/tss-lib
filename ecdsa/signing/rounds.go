// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	TaskName = "signing"
)

type (
	base struct {
		*tss.Parameters
		key     *keygen.LocalPartySaveData
		data    *SignatureData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- *SignatureData
		ok      []bool // `ok` tracks parties which have been verified by Update()
		started bool
		ended   bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
	round6 struct {
		*round5

		// Trigger for when a consistency check fails during Phase 5 of the protocol, resulting in a Type 5 identifiable abort (GG20)
		abortingT5 bool
	}
	round7AbortPrep struct {
		*round6
	}
	// The final round for the one-round signing mode (see the README)
	round7 struct {
		*round7AbortPrep
		abortingT7 bool
	}
	finalizationAbortPrep struct {
		*round7
	}
	finalization struct {
		*finalizationAbortPrep
	}
)

var (
	_ tss.PreprocessingRound = (*round1)(nil)
	_ tss.PreprocessingRound = (*round2)(nil)
	_ tss.PreprocessingRound = (*round3)(nil)
	_ tss.PreprocessingRound = (*round4)(nil)
	_ tss.PreprocessingRound = (*round5)(nil)
	_ tss.PreprocessingRound = (*round6)(nil)
	_ tss.PreprocessingRound = (*round7)(nil)
	_ tss.PreprocessingRound = (*round7AbortPrep)(nil)
	_ tss.PreprocessingRound = (*finalizationAbortPrep)(nil)
	_ tss.PreprocessingRound = (*finalization)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	return round.started && round.ended
}

func (round *base) Process(*tss.ParsedMessage, *tss.PartyID, *tss.GenericParameters) *tss.Error {
	return nil
}

func (round *base) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	round.ended = true
	return nil
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*tss.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

func SafeDoubleDictionaryGet(doubleDictionary map[string]map[string]interface{}, key string, Pj *tss.PartyID) (interface{}, bool) {
	if doubleDictionary == nil {
		return nil, false
	}
	val, ok := doubleDictionary[key]
	if !ok {
		return nil, ok
	}
	val2, ok2 := val[Pj.UniqueIDString()]
	return val2, ok2
}
