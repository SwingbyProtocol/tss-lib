// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"
	"strconv"
	"sync"

	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round5) InboundQueuesToConsume() []tss.QueueFunction {
	return []tss.QueueFunction{
		{round.temp.signRound1Message2sQ, &round.temp.signRound1Message2s, ProcessRound5PartI, true},
		{round.temp.signRound4MessagesQ, &round.temp.signRound4Messages, ProcessRound5PartII, true},
		{round.temp.signRound3MessagesQ, &round.temp.signRound3Messages, ProcessRound5PartIII, false},
	}
}

func (round *round5) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.ended = false
	round.resetOK()
	parameters := &tss.GenericParameters{Dictionary: make(map[string]interface{})}
	bigR := round.temp.gammaIG
	deltaI := *round.temp.deltaI
	deltaSum := &deltaI
	parameters.Dictionary["bigR"] = bigR
	parameters.Dictionary["deltaSum"] = deltaSum
	return parameters, nil
}

func ProcessRound5PartI(_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, _ sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	r1msg2 := (*msg).Content().(*SignRound1Message2)
	parameters.Dictionary["r1msg2"+strconv.Itoa(Pj.Index)] = r1msg2
	return parameters, nil
}

func ProcessRound5PartII(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, _ sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*round5)
	j := Pj.Index
	r1msg2 := parameters.Dictionary["r1msg2"+strconv.Itoa(j)].(*SignRound1Message2)
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

func ProcessRound5PartIII(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, _ sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	r3msg := (*msg).Content().(*SignRound3Message)
	deltaSum := parameters.Dictionary["deltaSum"].(*big.Int)
	modN := common.ModInt(tss.EC().Params().N)

	// calculating delta^-1 (below)
	deltaJ := r3msg.GetDeltaI()
	deltaSum = modN.Add(deltaSum, new(big.Int).SetBytes(deltaJ))
	parameters.Dictionary["deltaSum"] = deltaSum
	return parameters, nil
}

func (round *round5) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	Pi := round.PartyID()
	modN := common.ModInt(tss.EC().Params().N)
	deltaSum := parameters.Dictionary["deltaSum"].(*big.Int)
	bigR := parameters.Dictionary["bigR"].(*crypto.ECPoint)

	// compute the multiplicative inverse delta mod q
	deltaInv := modN.Inverse(deltaSum)

	// compute R and Rdash_i
	bigR = bigR.ScalarMult(deltaInv)
	round.temp.BigR = bigR.ToProtobufPoint()
	r := bigR.X()

	// used in FinalizeGetOurSigShare
	round.temp.RSigmaI = modN.Mul(r, round.temp.sigmaI).Bytes()

	// all parties broadcast Rdash_i = k_i * R
	kI := new(big.Int).SetBytes(round.temp.KI)
	bigRBarI := bigR.ScalarMult(kI)

	// compute ZK proof of consistency between R_i and E_i(k_i)
	// ported from: https://git.io/Jf69a
	pdlWSlackStatement := zkp.PDLwSlackStatement{
		PK:         &round.key.PaillierSK.PublicKey,
		CipherText: round.temp.cAKI,
		Q:          bigRBarI,
		G:          bigR,
		H1:         round.key.H1i,
		H2:         round.key.H2i,
		NTilde:     round.key.NTildei,
	}
	pdlWSlackWitness := zkp.PDLwSlackWitness{
		SK: round.key.PaillierSK,
		X:  kI,
		R:  round.temp.rAKI,
	}
	pdlWSlackPf := zkp.NewPDLwSlackProof(pdlWSlackWitness, pdlWSlackStatement)

	r5msg := NewSignRound5Message(Pi, bigRBarI, &pdlWSlackPf)
	round.out <- r5msg
	round.ended = true
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round5) CanProceed() bool {
	return round.started
}

func (round *round5) NextRound() tss.Round {
	round.started = false
	return &round6{round, false}
}
