// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round7) InboundQueuesToConsume() []tss.QueueFunction {
	return []tss.QueueFunction{
		{round.temp.signRound6MessagesQ, &round.temp.signRound6Messages, ProcessRound7, true},
		{round.temp.signRound3MessagesQII, &round.temp.signRound3Messages, ProcessRound7PartII, true},
	}
}

func (round *round7) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.ended = false
	parameters := &tss.GenericParameters{Dictionary: make(map[string]interface{}), DoubleDictionary: make(map[string]map[string]interface{})}
	culprits := make([]*tss.PartyID, 0, round.PartyCount())
	var multiErr error
	parameters.Dictionary["culprits"] = culprits
	parameters.Dictionary["multiErr"] = multiErr
	parameters.DoubleDictionary["calcDeltaJs"] = make(map[string]interface{})
	parameters.DoubleDictionary["bigSIs"] = make(map[string]interface{})
	parameters.DoubleDictionary["stProofs"] = make(map[string]interface{})

	var bigSJ = make(map[string]*common.ECPoint)
	parameters.Dictionary["bigSJ"] = bigSJ
	if !round.abortingT5 {
		bigSJProducts := round.temp.bigSI
		parameters.Dictionary["bigSJProducts"] = bigSJProducts
	}
	return parameters, nil
}

func ProcessRound7(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, _ sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round7)
	if round.abortingT5 {
		return processRound7Aborting(round_, msg, Pj, parameters)
	} else {
		return processRound7Normal(round_, msg, Pj, parameters)
	}
}

func processRound7Aborting(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round7)
	j := Pj.Index
	N := tss.EC().Params().N
	modN := common.ModInt(N)

	culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)
	r6msgInner, ok := (*msg).Content().(*SignRound6Message).GetContent().(*SignRound6Message_Abort)
	if !ok {
		common.Logger.Warnf("party %v round 7: unexpected success message while in aborting mode: %v %+v",
			round.PartyID(), *msg, r6msgInner)
		culprits = append(culprits, Pj)
		parameters.Dictionary["culprits"] = culprits
		return parameters, nil
	}
	r6msg := r6msgInner.Abort

	// Check that value gamma_j (in MtA) is consistent with bigGamma_j that is de-committed in Phase 4
	gammaJ := new(big.Int).SetBytes(r6msg.GetGammaI())
	gammaJG := crypto.ScalarBaseMult(tss.EC(), gammaJ)
	if !gammaJG.Equals(round.temp.bigGammaJs[j]) {
		culprits = append(culprits, Pj)
		parameters.Dictionary["culprits"] = culprits
		return parameters, nil
	}

	kJ := new(big.Int).SetBytes(r6msg.GetKI())
	calcDeltaJ := modN.Mul(kJ, gammaJ)
	for k, a := range r6msg.GetAlphaIJ() {
		if k == j {
			continue
		}
		if a == nil {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
			return parameters, nil
		}
		calcDeltaJ = modN.Add(calcDeltaJ, new(big.Int).SetBytes(a))
	}
	for k, b := range r6msg.GetBetaJI() {
		if k == j {
			continue
		}
		if b == nil {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
			return parameters, nil
		}
		calcDeltaJ = modN.Add(calcDeltaJ, new(big.Int).SetBytes(b))
	}
	parameters.DoubleDictionary["calcDeltaJs"][Pj.UniqueIDString()] = calcDeltaJ

	return parameters, nil
}

func processRound7Normal(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters) (*tss.GenericParameters, *tss.Error) {
	r := func(culpritsIn []*tss.PartyID, errIn *error, multiErrIn *error, PjIn *tss.PartyID,
		parametersIn *tss.GenericParameters, roundIn *round7) (*tss.GenericParameters, *tss.Error) {
		culpritsIn = append(culpritsIn, PjIn)
		*multiErrIn = multierror.Append(*multiErrIn, *errIn)
		parametersIn.Dictionary["culprits"] = culpritsIn
		parametersIn.Dictionary["multiErr"] = multiErrIn
		return parametersIn, roundIn.WrapError(*multiErrIn, culpritsIn...)
	}
	round := round_.(*round7)
	culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)
	var multiErr error
	if parameters.Dictionary["multiErr"] != nil {
		multiErr = parameters.Dictionary["multiErr"].(error)
	}
	r6msgInner, ok := (*msg).Content().(*SignRound6Message).GetContent().(*SignRound6Message_Success)
	if !ok {
		e := fmt.Errorf("unexpected abort message while in success mode: %v %+v",
			*msg, r6msgInner)
		return r(culprits, &e, &multiErr, Pj, parameters, round)
	}
	bigSJ := parameters.Dictionary["bigSJ"].(map[string]*common.ECPoint)
	r6msg := r6msgInner.Success
	bigSI, err := r6msg.UnmarshalSI()
	if err != nil {
		return r(culprits, &err, &multiErr, Pj, parameters, round)
	}
	parameters.DoubleDictionary["bigSIs"][Pj.UniqueIDString()] = bigSI
	bigSJ[Pj.Id] = bigSI.ToProtobufPoint()
	parameters.Dictionary["bigSJ"] = bigSJ

	stProof, err := r6msg.UnmarshalSTProof()
	if err != nil {
		return r(culprits, &err, &multiErr, Pj, parameters, round)
	}
	parameters.DoubleDictionary["stProofs"][Pj.UniqueIDString()] = stProof
	return parameters, nil
}

func ProcessRound7PartII(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, mutex sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round7)
	r3msg := (*msg).Content().(*SignRound3Message)
	culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)

	if round.abortingT5 {
		calcDeltaJ_, ok := parameters.DoubleDictionary["calcDeltaJs"][Pj.UniqueIDString()]
		if !ok {
			return parameters, nil
		}
		calcDeltaJ := calcDeltaJ_.(*big.Int)
		if expDeltaJ := new(big.Int).SetBytes(r3msg.GetDeltaI()); expDeltaJ.Cmp(calcDeltaJ) != 0 {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
		}
		return parameters, round.WrapError(errors.New("round 7 consistency check failed: g != R products, Type 5 identified abort, culprits known"), culprits...)
	} else {
		var multiErr error
		if parameters.Dictionary["multiErr"] != nil {
			multiErr = parameters.Dictionary["multiErr"].(error)
		}
		r := func(culpritsIn []*tss.PartyID, errIn *error, multiErrIn *error, PjIn *tss.PartyID,
			parametersIn *tss.GenericParameters, roundIn *round7) (*tss.GenericParameters, *tss.Error) {
			culpritsIn = append(culpritsIn, PjIn)
			*multiErrIn = multierror.Append(*multiErrIn, *errIn)
			parametersIn.Dictionary["culprits"] = culpritsIn
			parametersIn.Dictionary["multiErr"] = multiErrIn
			return parametersIn, roundIn.WrapError(*multiErrIn, culpritsIn...)
		}
		TI, err := r3msg.UnmarshalTI()
		if err != nil {
			return r(culprits, &err, &multiErr, Pj, parameters, round)
		}
		stProof := parameters.DoubleDictionary["stProofs"][Pj.UniqueIDString()].(*zkp.STProof)
		if err != nil {
			return r(culprits, &err, &multiErr, Pj, parameters, round)
		}
		bigSI := parameters.DoubleDictionary["bigSIs"][Pj.UniqueIDString()].(*crypto.ECPoint)

		// bigR is stored as bytes for the OneRoundData protobuf struct
		bigRX, bigRY := new(big.Int).SetBytes(round.temp.BigR.GetX()), new(big.Int).SetBytes(round.temp.BigR.GetY())
		bigR := crypto.NewECPointNoCurveCheck(tss.EC(), bigRX, bigRY)
		parameters.Dictionary["bigR"] = bigR
		h, errH := crypto.ECBasePoint2(tss.EC())
		if errH != nil {
			return parameters, round.WrapError(errH, round.PartyID())
		}

		if ok := stProof.Verify(bigSI, TI, bigR, h); !ok {
			e := errors.New("STProof verify failure")
			return r(culprits, &e, &multiErr, Pj, parameters, round)
		}
		mutex.Lock()
		bigSJProducts := parameters.Dictionary["bigSJProducts"].(*crypto.ECPoint)
		// bigSI consistency check
		if bigSJProducts, err = bigSJProducts.Add(bigSI); err != nil {
			mutex.Unlock()
			return r(culprits, &err, &multiErr, Pj, parameters, round)
		}
		parameters.Dictionary["bigSJProducts"] = bigSJProducts
		mutex.Unlock()

		if 0 < len(culprits) {
			return parameters, round.WrapError(multiErr, culprits...)
		}
		return parameters, nil
	}
}

func (round *round7) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	Pi := round.PartyID()
	var culprits []*tss.PartyID
	if parameters.Dictionary["culprits"] != nil {
		culprits = parameters.Dictionary["culprits"].([]*tss.PartyID)
	}
	var multiErr error
	if parameters.Dictionary["multiErr"] != nil {
		multiErr = parameters.Dictionary["multiErr"].(error)
	}
	bigR := parameters.Dictionary["bigR"].(*crypto.ECPoint)
	bigSJ := parameters.Dictionary["bigSJ"].(map[string]*common.ECPoint)
	bigSJProducts := parameters.Dictionary["bigSJProducts"].(*crypto.ECPoint)

	if 0 < len(culprits) {
		return round.WrapError(multiErr, culprits...)
	}

	round.temp.rI = bigR
	round.temp.BigSJ = bigSJ
	if y := round.key.ECDSAPub; !bigSJProducts.Equals(y) {
		round.abortingT7 = true
		common.Logger.Warnf("party %v round 7: consistency check failed: y != bigSJ products, entering Type 7 identified abort",
			Pi)

		// If we abort here, one-round mode won't matter now - we will proceed to round "8" anyway.
		r7msg := NewSignRound7MessageAbort(Pi, &round.temp.r7AbortData)
		round.out <- r7msg
		round.ended = true
		return nil
	}

	// PRE-PROCESSING FINISHED
	// If we are in one-round signing mode (msg is nil), we will exit out with the current state here and we are done.
	round.temp.T = int32(len(round.Parties().IDs()) - 1)
	round.data.OneRoundData = &round.temp.SignatureData_OneRoundData
	if round.temp.m == nil {
		round.end <- round.data
		for j := range round.ok {
			round.ok[j] = true
		}
		return nil
	}

	// Continuing the full online protocol.
	sI := FinalizeGetOurSigShare(round.data, round.temp.m)
	round.temp.sI = sI

	r7msg := NewSignRound7MessageSuccess(round.PartyID(), sI)
	round.out <- r7msg
	round.ended = true
	return nil
}

func (round *round7) CanProcess(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound6Message).GetContent().(*SignRound6Message_Abort); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound6Message).GetContent().(*SignRound6Message_Success); ok {
		return msg.IsBroadcast()
	}
	return false
}

//
func (round *round7) CanProceed() bool {
	c := round.started && round.ended && round.temp.signRound7MessagesQ.Len() >= int64(round.PartyCount()-1)
	return c
}

func (round *round7) NextRound() tss.Round {
	// If we are in one-round signing mode (msg is nil), we will exit out with the current state here and there are no further rounds.
	if !round.abortingT7 && round.temp.m == nil {
		return nil
	}
	// Continuing the full online protocol.
	round.started = false
	if !round.abortingT7 {
		// wipe sensitive data for gc, not used from here
		round.temp.r7AbortData = SignRound7Message_AbortData{}

		return &finalization{&finalizationAbortPrep{round}}
	}
	return &finalizationAbortPrep{round}
}
