// Copyright © 2021 Swingby

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

func (round *round6) InboundQueuesToConsume() []tss.QueueFunction {
	return []tss.QueueFunction{
		{round.temp.signRound5MessagesQ, &round.temp.signRound5Messages, ProcessRound6PartI, true},
		{round.temp.signRound1Message1sQII, &round.temp.signRound1Message1s, ProcessRound6PartII, true},
	}
}

func (round *round6) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.ended = false
	parameters := &tss.GenericParameters{Dictionary: make(map[string]interface{}), DoubleDictionary: make(map[string]map[string]interface{})}

	errs := make(map[string]interface{})
	pdlWSlackPfs := make(map[string]interface{})
	bigRBarJs := make(map[string]interface{})
	bigRBarJProducts := (*crypto.ECPoint)(nil)
	BigRBarJ := make(map[string]*common.ECPoint, round.Params().PartyCount())
	parameters.DoubleDictionary["errs"] = errs
	parameters.DoubleDictionary["pdlWSlackPfs"] = pdlWSlackPfs
	parameters.DoubleDictionary["bigRBarJs"] = bigRBarJs

	kI := new(big.Int).SetBytes(round.temp.KI)
	bigR, _ := crypto.NewECPointFromProtobuf(round.temp.BigR)
	bigRBarI := bigR.ScalarMult(kI)
	bigRBarJProducts = bigRBarI

	parameters.Dictionary["bigRBarJProducts"] = bigRBarJProducts
	parameters.Dictionary["BigRBarJ"] = BigRBarJ
	return parameters, nil
}

func ProcessRound6PartI(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, mutex sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round6)
	i := round.PartyID().Index
	j := Pj.Index

	BigRBarJ := parameters.Dictionary["BigRBarJ"].(map[string]*common.ECPoint)
	bigRBarJProducts := parameters.Dictionary["bigRBarJProducts"].(*crypto.ECPoint)

	r5msg := (*msg).Content().(*SignRound5Message)
	bigRBarJ, err := r5msg.UnmarshalRI()
	if err != nil {
		parameters.DoubleDictionary["errs"][Pj.UniqueIDString()] = struct {
			e error
			p tss.PartyID
		}{err, *Pj}
		return parameters, round.WrapError(err)
	}
	parameters.DoubleDictionary["bigRBarJs"][Pj.UniqueIDString()] = bigRBarJ
	BigRBarJ[Pj.Id] = bigRBarJ.ToProtobufPoint()
	parameters.Dictionary["BigRBarJ"] = BigRBarJ

	mutex.Lock()
	// find products of all Rdash_i to ensure it equals the G point of the curve
	if bigRBarJProducts, err = bigRBarJProducts.Add(bigRBarJ); err != nil {
		parameters.DoubleDictionary["errs"][Pj.UniqueIDString()] = struct {
			e error
			p tss.PartyID
		}{err, *Pj}
		mutex.Unlock()
		return parameters, round.WrapError(err)
	}
	mutex.Unlock()
	parameters.Dictionary["bigRBarJProducts"] = bigRBarJProducts

	if j == i {
		return parameters, nil
	}
	// verify ZK proof of consistency between R_i and E_i(k_i)
	// ported from: https://git.io/Jf69a
	pdlWSlackPf, err := r5msg.UnmarshalPDLwSlackProof()
	if err != nil {
		parameters.DoubleDictionary["errs"][Pj.UniqueIDString()] = struct {
			e error
			p tss.PartyID
		}{err, *Pj}
		return parameters, round.WrapError(err)
	}
	parameters.DoubleDictionary["pdlWSlackPfs"][Pj.UniqueIDString()] = pdlWSlackPf
	return parameters, nil
}

func ProcessRound6PartII(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, mutex sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round6)
	j := Pj.Index
	r1msg1 := (*msg).Content().(*SignRound1Message1)
	pdlWSlackPf := parameters.DoubleDictionary["pdlWSlackPfs"][Pj.UniqueIDString()].(*zkp.PDLwSlackProof)
	bigRBarJ := parameters.DoubleDictionary["bigRBarJs"][Pj.UniqueIDString()].(*crypto.ECPoint)

	bigR, _ := crypto.NewECPointFromProtobuf(round.temp.BigR)
	pdlWSlackStatement := zkp.PDLwSlackStatement{
		PK:         round.key.PaillierPKs[Pj.Index],
		CipherText: new(big.Int).SetBytes(r1msg1.GetC()),
		Q:          bigRBarJ,
		G:          bigR,
		H1:         round.key.H1j[Pj.Index],
		H2:         round.key.H2j[Pj.Index],
		NTilde:     round.key.NTildej[Pj.Index], // maybe i
	}

	if !pdlWSlackPf.Verify(pdlWSlackStatement) {
		err := fmt.Errorf("failed to verify ZK proof of consistency between R_i and E_i(k_i) for P %d", j)
		mutex.Lock()
		parameters.DoubleDictionary["errs"][Pj.UniqueIDString()] = struct {
			e error
			p tss.PartyID
		}{err, *Pj}
		mutex.Unlock()
		return parameters, nil
	}
	return parameters, nil
}

func (round *round6) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	Pi := round.PartyID()
	errs := parameters.DoubleDictionary["errs"]
	bigRBarJProducts := parameters.Dictionary["bigRBarJProducts"].(*crypto.ECPoint)
	BigRBarJ := parameters.Dictionary["BigRBarJ"].(map[string]*common.ECPoint)
	bigR, _ := crypto.NewECPointFromProtobuf(round.temp.BigR)
	sigmaI := round.temp.sigmaI
	defer func() {
		round.temp.sigmaI.Set(zero)
		round.temp.sigmaI = zero
	}()

	if 0 < len(errs) {
		var multiErr error
		culprits := make([]*tss.PartyID, 0, len(errs))
		for _, err_ := range errs {
			err := err_.(struct {
				e error
				p tss.PartyID
			})
			multiErr = multierror.Append(multiErr, err.e)
			culprits = append(culprits, &err.p)
		}
		return round.WrapError(multiErr, culprits...)
	}
	{
		ec := tss.EC()
		gX, gY := ec.Params().Gx, ec.Params().Gy
		if bigRBarJProducts.X().Cmp(gX) != 0 || bigRBarJProducts.Y().Cmp(gY) != 0 {
			round.abortingT5 = true
			common.Logger.Warnf("party %v round 6: consistency check failed: g != R products, entering Type 5 identified abort", Pi)

			r6msg := NewSignRound6MessageAbort(Pi, &round.temp.r5AbortData)
			round.out <- r6msg
			round.ended = true
			return nil
		}
	}

	round.temp.BigRBarJ = BigRBarJ

	// R^sigma_i proof used in type 7 aborts
	bigSI := bigR.ScalarMult(sigmaI)
	{
		sigmaPf, err := zkp.NewECSigmaIProof(tss.EC(), sigmaI, bigR, bigSI)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		round.temp.r7AbortData.EcddhProofA1 = sigmaPf.A1.ToProtobufPoint()
		round.temp.r7AbortData.EcddhProofA2 = sigmaPf.A2.ToProtobufPoint()
		round.temp.r7AbortData.EcddhProofZ = sigmaPf.Z.Bytes()
	}
	round.temp.bigSI = bigSI
	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	TI, lI := round.temp.TI, round.temp.lI
	stPf, err := zkp.NewSTProof(TI, bigR, h, sigmaI, lI)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	// wipe sensitive data for gc
	round.temp.lI.Set(zero)
	round.temp.TI, round.temp.lI = nil, nil

	r6msg := NewSignRound6MessageSuccess(Pi, bigSI, stPf)
	round.out <- r6msg
	round.ended = true
	return nil
}

func (round *round6) CanProcess(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound5Message); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round6) CanProceed() bool {
	c := round.started && round.ended && round.temp.signRound6MessagesQ.Len() >= int64(round.PartyCount()-1)
	return c
}

func (round *round6) NextRound() tss.Round {
	round.started = false
	if !round.abortingT5 {
		// wipe sensitive data for gc, not used from here
		round.temp.r5AbortData = SignRound6Message_AbortData{}

		return &round7{&round7AbortPrep{round}, false}
	}
	return &round7AbortPrep{round}
}
