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
	"strconv"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round7) InboundQueuesToConsume() []tss.QueueFunction {
	return []tss.QueueFunction{
		{round.temp.signRound6MessagesQ, &round.temp.signRound6Messages, ProcessRound7, true},
		{round.temp.signRound3MessagesQII, &round.temp.signRound3Messages, ProcessRound7PartII, false},
	}
}

func (round *round7) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.ended = false
	round.resetOK()
	parameters := &tss.GenericParameters{Dictionary: make(map[string]interface{})}
	culprits := make([]*tss.PartyID, 0, round.PartyCount())
	var multiErr error
	parameters.Dictionary["culprits"] = culprits
	parameters.Dictionary["multiErr"] = multiErr
	var bigSJ = make(map[string]*common.ECPoint)
	parameters.Dictionary["bigSJ"] = bigSJ
	if !round.abortingT5 {
		bigSJProducts := round.temp.bigSI
		// common.Logger.Debugf("party %v, bigSJProducts: %v (init)", round.PartyID(), FormatECPoint(bigSJProducts))
		parameters.Dictionary["bigSJProducts"] = bigSJProducts
	}
	return parameters, nil
}

func ProcessRound7(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters) (*tss.GenericParameters, *tss.Error) {
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
		common.Logger.Warnf("round 7: unexpected success message while in aborting mode: %+v", r6msgInner)
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
	parameters.Dictionary["calcDeltaJ"+strconv.Itoa(Pj.Index)] = calcDeltaJ
	return parameters, nil
}

func processRound7Normal(round tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters) (*tss.GenericParameters, *tss.Error) {
	r6msgInner, ok := (*msg).Content().(*SignRound6Message).GetContent().(*SignRound6Message_Success)
	culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)
	var multiErr error
	if parameters.Dictionary["multiErr"] != nil {
		multiErr = parameters.Dictionary["multiErr"].(error)
	}
	bigSJ := parameters.Dictionary["bigSJ"].(map[string]*common.ECPoint)
	if !ok {
		culprits = append(culprits, Pj)
		multiErr = multierror.Append(multiErr, fmt.Errorf("unexpected abort message while in success mode: %+v", r6msgInner))
		parameters.Dictionary["culprits"] = culprits
		parameters.Dictionary["multiErr"] = multiErr
		return parameters, round.WrapError(multiErr, culprits...)
	}
	r6msg := r6msgInner.Success
	bigSI, err := r6msg.UnmarshalSI()
	if err != nil {
		culprits = append(culprits, Pj)
		multiErr = multierror.Append(multiErr, err)
		parameters.Dictionary["culprits"] = culprits
		parameters.Dictionary["multiErr"] = multiErr
		return parameters, round.WrapError(multiErr, culprits...)
	}
	parameters.Dictionary["bigSI"+strconv.Itoa(Pj.Index)] = bigSI
	bigSJ[Pj.Id] = bigSI.ToProtobufPoint()
	parameters.Dictionary["bigSJ"] = bigSJ

	stProof, err := r6msg.UnmarshalSTProof()
	if err != nil {
		culprits = append(culprits, Pj)
		multiErr = multierror.Append(multiErr, err)
		parameters.Dictionary["culprits"] = culprits
		parameters.Dictionary["multiErr"] = multiErr
		return parameters, round.WrapError(multiErr, culprits...)
	}
	parameters.Dictionary["stProof"+strconv.Itoa(Pj.Index)] = stProof
	return parameters, nil
}

func ProcessRound7PartII(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round7)
	r3msg := (*msg).Content().(*SignRound3Message)
	culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)

	if round.abortingT5 {
		calcDeltaJ := parameters.Dictionary["calcDeltaJ"+strconv.Itoa(Pj.Index)].(*big.Int)
		if expDeltaJ := new(big.Int).SetBytes(r3msg.GetDeltaI()); expDeltaJ.Cmp(calcDeltaJ) != 0 {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
		}
		return parameters, round.WrapError(errors.New("round 6 consistency check failed: g != R products, Type 5 identified abort, culprits known"), culprits...)
	} else {
		var multiErr error
		if parameters.Dictionary["multiErr"] != nil {
			multiErr = parameters.Dictionary["multiErr"].(error)
		}
		TI, err := r3msg.UnmarshalTI()
		if err != nil {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, err)
			parameters.Dictionary["culprits"] = culprits
			parameters.Dictionary["multiErr"] = multiErr
			return parameters, round.WrapError(multiErr, culprits...)
		}
		stProof := parameters.Dictionary["stProof"+strconv.Itoa(Pj.Index)].(*zkp.STProof)
		if err != nil {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, err)
			parameters.Dictionary["culprits"] = culprits
			parameters.Dictionary["multiErr"] = multiErr
			return parameters, round.WrapError(multiErr, culprits...)
		}
		bigSI := parameters.Dictionary["bigSI"+strconv.Itoa(Pj.Index)].(*crypto.ECPoint)

		// bigR is stored as bytes for the OneRoundData protobuf struct
		bigRX, bigRY := new(big.Int).SetBytes(round.temp.BigR.GetX()), new(big.Int).SetBytes(round.temp.BigR.GetY())
		bigR := crypto.NewECPointNoCurveCheck(tss.EC(), bigRX, bigRY)
		parameters.Dictionary["bigR"] = bigR
		h, errH := crypto.ECBasePoint2(tss.EC())
		if errH != nil {
			return parameters, round.WrapError(errH, round.PartyID())
		}

		common.Logger.Debugf("party %v r7 Pj %v, bigSI %v, TI %v, bigR %v, h %v", round.PartyID(), Pj,
			FormatECPoint(bigSI),
			FormatECPoint(TI), FormatECPoint(bigR), FormatECPoint(h))
		if ok := stProof.Verify(bigSI, TI, bigR, h); !ok {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, errors.New("STProof verify failure"))
			common.Logger.Errorf("party %v error STProof verify failure", round.PartyID()) // TODO
			parameters.Dictionary["culprits"] = culprits
			parameters.Dictionary["multiErr"] = multiErr
			return parameters, round.WrapError(multiErr, culprits...)
		}
		bigSJProducts := parameters.Dictionary["bigSJProducts"].(*crypto.ECPoint)
		// common.Logger.Debugf("party %v, Pj: %v, r7 bigSJProducts: %v (before)", round.PartyID(), Pj,
		//	FormatECPoint(bigSJProducts)) TODO
		// bigSI consistency check
		if bigSJProducts, err = bigSJProducts.Add(bigSI); err != nil {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, err)
			// common.Logger.Errorf("party %v error bigSJProducts.Add", round.PartyID()) // TODO
			parameters.Dictionary["culprits"] = culprits
			parameters.Dictionary["multiErr"] = multiErr
			return parameters, round.WrapError(multiErr, culprits...)
		}
		parameters.Dictionary["bigSJProducts"] = bigSJProducts
		// common.Logger.Debugf("party %v, Pj: %v, r7 bigSJProducts: %v (after)", round.PartyID(), Pj,
		// 	FormatECPoint(bigSJProducts))

		if 0 < len(culprits) {
			return parameters, round.WrapError(multiErr, culprits...)
		}
		return parameters, nil
	}
}

func (round *round7) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	Pi := round.PartyID()
	var culprits []*tss.PartyID
	common.Logger.Debugf("party %v r7 Postprocess step 1", Pi)
	if parameters == nil {
		common.Logger.Errorf("party %v error", Pi) // TODO
		return round.WrapError(errors.New("parameters is null"))
	}
	if parameters.Dictionary["culprits"] != nil {
		culprits = parameters.Dictionary["culprits"].([]*tss.PartyID)
	}
	var multiErr error
	if parameters.Dictionary["multiErr"] != nil {
		multiErr = parameters.Dictionary["multiErr"].(error)
	}
	if _, ok := parameters.Dictionary["bigR"]; !ok { // TODO
		for {
			common.Logger.Warnf("party %v warning bigR", Pi) // TODO
			time.Sleep(20 * time.Second)
		}
	}
	bigR := parameters.Dictionary["bigR"].(*crypto.ECPoint)
	bigSJ := parameters.Dictionary["bigSJ"].(map[string]*common.ECPoint)
	bigSJProducts := parameters.Dictionary["bigSJProducts"].(*crypto.ECPoint)

	if 0 < len(culprits) {
		return round.WrapError(multiErr, culprits...)
	}
	common.Logger.Debugf("party %v r7 Postprocess step 2", Pi)

	round.temp.rI = bigR
	round.temp.BigSJ = bigSJ
	common.Logger.Debugf("party %v, y: %v, bigSJProducts: %v", Pi, FormatECPoint(round.key.ECDSAPub),
		FormatECPoint(bigSJProducts))
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
	common.Logger.Debugf("party %v r7 Postprocess step 3", Pi)

	// Continuing the full online protocol.
	sI := FinalizeGetOurSigShare(round.data, round.temp.m)
	round.temp.sI = sI

	r7msg := NewSignRound7MessageSuccess(round.PartyID(), sI)
	round.out <- r7msg
	round.ended = true
	return nil
}

func (round *round7) CanAccept(msg tss.ParsedMessage) bool {
	// Collect messages for the full online protocol OR identified abort of type 7.
	if _, ok := msg.Content().(*SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

//
func (round *round7) CanProceed() bool {
	c := round.started && round.ended && round.temp.signRound7MessagesQ.Len() >= int64(round.PartyCount()-1)
	common.Logger.Debugf("party %v, round7 CanProceed? %v", round.PartyID(), c)
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
