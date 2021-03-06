// Copyright © 2021 Swingby

package signing

import (
	"errors"
	"math/big"
	"sync"

	errorspkg "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) InboundQueuesToConsume() []tss.QueueFunction {
	return []tss.QueueFunction{
		{round.temp.signRound2MessagesQ, &round.temp.signRound2Messages, ProcessRound3, true},
	}
}

func (round *round3) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.ended = false

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)
	parameters := &tss.GenericParameters{Dictionary: make(map[string]interface{}), DoubleDictionary: make(map[string]map[string]interface{})}
	parameters.Dictionary["errChs"] = errChs
	parameters.DoubleDictionary["alphaIJs"] = make(map[string]interface{})

	// mod q'd
	parameters.DoubleDictionary["muIJs"] = make(map[string]interface{})

	// raw recovered
	parameters.DoubleDictionary["muIJRecs"] = make(map[string]interface{})

	parameters.DoubleDictionary["muRandIJ"] = make(map[string]interface{})
	parameters.Dictionary["wgp"] = &wg
	parameters.Dictionary["roundMutex"] = &sync.RWMutex{}
	return parameters, nil
}

func ProcessRound3(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID,
	parameters *tss.GenericParameters, _ *sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round3)
	wg := parameters.Dictionary["wgp"].(*sync.WaitGroup)
	errChs := parameters.Dictionary["errChs"].(chan *tss.Error)
	roundMutex := parameters.Dictionary["roundMutex"].(*sync.RWMutex)

	i := round.PartyID().Index
	j := Pj.Index
	r2msg := (*msg).Content().(*SignRound2Message)

	// Alice_end
	go func(j int, Pj *tss.PartyID) {
		defer wg.Done()
		proofBob, err := r2msg.UnmarshalProofBob()
		if err != nil {
			errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalProofBob failed"), Pj)
			return
		}
		alphaIJ, err := mta.AliceEnd(
			round.key.PaillierPKs[i],
			proofBob,
			round.key.H1j[i],
			round.key.H2j[i],
			round.temp.c1Is[j],
			new(big.Int).SetBytes(r2msg.GetC1()),
			round.key.NTildej[i],
			round.key.PaillierSK)
		if err != nil {
			errChs <- round.WrapError(err, Pj)
			return
		}
		roundMutex.Lock()
		parameters.DoubleDictionary["alphaIJs"][Pj.UniqueIDString()] = alphaIJ
		round.temp.r5AbortData.AlphaIJ[j] = alphaIJ.Bytes()
		roundMutex.Unlock()
	}(j, Pj)
	// Alice_end_wc
	go func(j int, Pj *tss.PartyID) {
		defer wg.Done()
		proofBobWC, err := r2msg.UnmarshalProofBobWC()
		if err != nil {
			errChs <- round.WrapError(errorspkg.Wrapf(err, "MtA: UnmarshalProofBobWC failed"), Pj)
			return
		}
		muIJ, muIJRec, muIJRand, err := mta.AliceEndWC(
			round.key.PaillierPKs[i],
			proofBobWC,
			round.temp.bigWs[j],
			round.temp.c1Is[j],
			new(big.Int).SetBytes(r2msg.GetC2()),
			round.key.NTildej[i],
			round.key.H1j[i],
			round.key.H2j[i],
			round.key.PaillierSK)
		if err != nil {
			errChs <- round.WrapError(err, Pj)
			return
		}
		roundMutex.Lock()
		parameters.DoubleDictionary["muIJs"][Pj.UniqueIDString()] = muIJ       // mod q'd
		parameters.DoubleDictionary["muIJRecs"][Pj.UniqueIDString()] = muIJRec // raw recovered
		parameters.DoubleDictionary["muRandIJ"][Pj.UniqueIDString()] = muIJRand
		roundMutex.Unlock()
	}(j, Pj)

	return parameters, nil
}

func (round *round3) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	wg := parameters.Dictionary["wgp"].(*sync.WaitGroup)
	// consume error channels; wait for goroutines
	wg.Wait()
	Pi := round.PartyID()
	i := Pi.Index
	errChs := parameters.Dictionary["errChs"].(chan *tss.Error)
	muIJRecsA := make([]*big.Int, len(round.Parties().IDs())) // raw recovered
	muRandIJA := make([]*big.Int, len(round.Parties().IDs()))
	muIJRecs := parameters.DoubleDictionary["muIJRecs"]
	muRandIJ := parameters.DoubleDictionary["muRandIJ"]
	alphaIJs := parameters.DoubleDictionary["alphaIJs"]
	muIJs := parameters.DoubleDictionary["muIJs"]

	// consume error channels; wait for goroutines
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate Alice_end or Alice_end_wc"), culprits...)
	}

	q := tss.EC().Params().N
	modN := common.ModInt(q)

	kI := new(big.Int).SetBytes(round.temp.KI)
	deltaI := modN.Mul(kI, round.temp.gammaI)
	sigmaI := modN.Mul(kI, round.temp.wI)

	// clear wI from temp memory
	round.temp.wI.Set(zero)
	round.temp.wI = zero

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		alphaIJj := alphaIJs[Pj.UniqueIDString()].(*big.Int)
		muIJsj := muIJs[Pj.UniqueIDString()].(*big.Int)
		muIJRecsA[j] = muIJRecs[Pj.UniqueIDString()].(*big.Int)
		muRandIJA[j] = muRandIJ[Pj.UniqueIDString()].(*big.Int)
		beta := modN.Sub(zero, round.temp.vJIs[j])
		deltaI.Add(deltaI, alphaIJj.Add(alphaIJj, round.temp.betas[j]))
		sigmaI.Add(sigmaI, muIJsj.Add(muIJsj, beta))
		deltaI.Mod(deltaI, q)
		sigmaI.Mod(sigmaI, q)
	}

	// for identifying aborts in round 7: muIJs, revealed during Type 7 identified abort
	round.temp.r7AbortData.MuIJ = common.BigIntsToBytes(muIJRecsA)
	round.temp.r7AbortData.MuRandIJ = common.BigIntsToBytes(muRandIJA)

	// nil sensitive data for gc
	round.temp.betas, round.temp.vJIs = nil, nil

	// gg20: calculate T_i = g^sigma_i h^l_i
	lI := common.GetRandomPositiveInt(q)
	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}
	hLI := h.ScalarMult(lI)
	gSigmaI := crypto.ScalarBaseMult(tss.EC(), sigmaI)
	TI, err := gSigmaI.Add(hLI)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	// gg20: generate the ZK proof of T_i, verified in ValidateBasic for the round 3 message
	tProof, err := zkp.NewTProof(TI, h, sigmaI, lI)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	round.temp.TI = TI
	round.temp.lI = lI
	round.temp.deltaI = deltaI
	round.temp.sigmaI = sigmaI

	r3msg := NewSignRound3Message(Pi, deltaI, TI, tProof)
	round.out <- r3msg
	round.ended = true
	return nil
}

func (round *round3) CanProcess(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) CanProceed() bool {
	return round.started
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
