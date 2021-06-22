// Copyright © 2021 Swingby

package signing

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) InboundQueuesToConsume() []tss.QueueFunction {
	return []tss.QueueFunction{
		{round.temp.signRound1Message2sQ, &round.temp.signRound1Message2s, ProcessRound4PartI, true},
		{round.temp.signRound4MessagesQ, &round.temp.signRound4Messages, ProcessRound4PartII, true},
		{round.temp.signRound3MessagesQ, &round.temp.signRound3Messages, ProcessRound4PartIII, true},
	}
}

func (round *round4) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.ended = false

	Pi := round.PartyID()

	r4msg := NewSignRound4Message(Pi, round.temp.deCommit)
	round.out <- r4msg

	parameters := &tss.GenericParameters{Dictionary: make(map[string]interface{}), DoubleDictionary: make(map[string]map[string]interface{})}
	bigR := round.temp.gammaIG
	deltaI := *round.temp.deltaI
	deltaSum := &deltaI
	parameters.Dictionary["bigR"] = bigR
	parameters.Dictionary["deltaSum"] = deltaSum
	parameters.DoubleDictionary["r1msg2s"] = make(map[string]interface{})
	parameters.DoubleDictionary["waitGroups"] = make(map[string]interface{})
	// One wait group for the other players to synchronize the order of
	// message reads for the different types of messages
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		wgj := &sync.WaitGroup{}
		wgj.Add(1)
		parameters.DoubleDictionary["waitGroups"][Pj.UniqueIDString()] = wgj
	}
	round.ended = true
	return parameters, nil

}

func ProcessRound4PartI(round tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, _ *sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	r1msg2 := (*msg).Content().(*SignRound1Message2)
	parameters.DoubleDictionary["r1msg2s"][Pj.UniqueIDString()] = r1msg2
	wgj_, ok := SafeDoubleDictionaryGet(parameters.DoubleDictionary, "waitGroups", Pj)
	if !ok {
		return parameters, round.WrapError(fmt.Errorf("waitGroups error for party %v", Pj))
	}
	wgj := wgj_.(*sync.WaitGroup)
	wgj.Done()
	return parameters, nil
}

func ProcessRound4PartII(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, _ *sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round4)
	j := Pj.Index
	wgj_, ok := SafeDoubleDictionaryGet(parameters.DoubleDictionary, "waitGroups", Pj)
	if !ok {
		return parameters, round.WrapError(fmt.Errorf("waitGroups error for party %v", Pj))
	}
	wgj := wgj_.(*sync.WaitGroup)
	wgj.Wait()
	r1msg2 := parameters.DoubleDictionary["r1msg2s"][Pj.UniqueIDString()].(*SignRound1Message2)
	bigR := parameters.Dictionary["bigR"].(*crypto.ECPoint)

	r4msg := (*msg).Content().(*SignRound4Message)

	// calculating Big R
	SCj, SDj := r1msg2.UnmarshalCommitment(), r4msg.UnmarshalDeCommitment()
	cmtDeCmt := commitments.HashCommitDecommit{C: SCj, D: SDj}
	ok, bigGammaJ := cmtDeCmt.DeCommit()
	if !ok || len(bigGammaJ) != 2 {
		return parameters, round.WrapError(errors.New("commitment verify failed"), Pj)
	}
	bigGammaJPoint, err := crypto.NewECPoint(tss.EC(), bigGammaJ[0], bigGammaJ[1])
	if err != nil {
		return parameters, round.WrapError(errors2.Wrapf(err, "NewECPoint(bigGammaJ)"), Pj)
	}
	round.temp.bigGammaJs[j] = bigGammaJPoint // used for identifying abort in round 7
	bigR, err = bigR.Add(bigGammaJPoint)
	if err != nil {
		return parameters, round.WrapError(errors2.Wrapf(err, "bigR.Add(bigGammaJ)"), Pj)
	}
	parameters.Dictionary["bigR"] = bigR
	return parameters, nil
}

func ProcessRound4PartIII(_ tss.PreprocessingRound, msg *tss.ParsedMessage, _ *tss.PartyID,
	parameters *tss.GenericParameters, mutex *sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	r3msg := (*msg).Content().(*SignRound3Message)
	mutex.Lock()
	deltaSum := parameters.Dictionary["deltaSum"].(*big.Int)
	mutex.Unlock()
	modN := common.ModInt(tss.EC().Params().N)

	// calculating delta^-1 (below)
	deltaJ := r3msg.GetDeltaI()
	deltaSum = modN.Add(deltaSum, new(big.Int).SetBytes(deltaJ))
	mutex.Lock()
	parameters.Dictionary["deltaSum"] = deltaSum
	mutex.Unlock()
	return parameters, nil
}

func (round *round4) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	modN := common.ModInt(tss.EC().Params().N)
	deltaSum := parameters.Dictionary["deltaSum"].(*big.Int)
	bigR := parameters.Dictionary["bigR"].(*crypto.ECPoint)

	// compute the multiplicative inverse delta mod q
	deltaInv := modN.Inverse(deltaSum)

	// compute R
	bigR = bigR.ScalarMult(deltaInv)
	round.temp.BigR = bigR.ToProtobufPoint()
	return nil
}

func (round *round4) CanProcess(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message2); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) CanProceed() bool {
	return round.started && round.ended
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
