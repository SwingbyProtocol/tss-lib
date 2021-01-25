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
	"math/rand"
	"time"

	"github.com/Workiva/go-datastructures/queue"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/mta"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, false,1}}
}

func (round *round1) Start() *tss.Error {
	common.Logger.Debug("round_1 Start") // TODO
	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	/* for j, msg1 := range round.temp.signRound1Message1s {
		if round.ok[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		msg2 := round.temp.signRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	} */
	return true, nil
}

//
func (round *round1) CanProceed() bool {
	common.Logger.Debugf("party %v round %v proceed? %v", round.PartyID(), round.number, round.ended)
	return round.ended
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round1: round}
}

func (round *round1) InboundQueuesToConsume() []*queue.Queue {
	return nil
}

func (round *round1) OutboundQueuesWrittenTo() []*queue.Queue {
	q := make([]*queue.Queue, 2)
	q = append(q, round.temp.signRound1Message1s)
	q = append(q, round.temp.signRound1Message2s)
	return q
}

/* */
func (round *round1) Preprocess() (*tss.GenericParameters, *tss.Error) {
	round.number = 1
	round.started = true
	round.ended = false
	round.resetOK()

	err2 := round.prepare()
	if err2 != nil {
		return nil, round.WrapError(err2)
	}

	// Spec requires calculate H(M) here,
	// but considered different blockchain use different hash function we accept the converted big.Int
	// if this big.Int is not belongs to Zq, the client might not comply with common rule (for ECDSA):
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L263
	if round.temp.m != nil &&
		round.temp.m.Cmp(tss.EC().Params().N) >= 0 {
		return nil, round.WrapError(errors.New("hashed message is not valid"))
	}

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	dict := make(map[string]interface{})
	parameters := &tss.GenericParameters{Dictionary: dict}
	gammaI := common.GetRandomPositiveInt(tss.EC().Params().N)
	kI := common.GetRandomPositiveInt(tss.EC().Params().N)
	round.temp.gammaI = gammaI
	round.temp.r5AbortData.GammaI = gammaI.Bytes()
	gammaIG := crypto.ScalarBaseMult(tss.EC(), gammaI)
	round.temp.gammaIG = gammaIG
	cmt := commitments.NewHashCommitment(gammaIG.X(), gammaIG.Y())
	round.temp.deCommit = cmt.D
	parameters.Dictionary["cmt.C"] = cmt.C

	// MtA round 1
	paiPK := round.key.PaillierPKs[i]

	cA, rA, err := paiPK.EncryptAndReturnRandomness(kI)
	if err != nil {
		return nil, round.WrapError(err, Pi)
	}

	// set "k"-related temporary variables, also used for identified aborts later in the protocol
	{
		kIBz := kI.Bytes()
		round.temp.KI = kIBz // now part of the OneRoundData struct
		round.temp.r5AbortData.KI = kIBz
		round.temp.r7AbortData.KI = kIBz
		round.temp.cAKI = cA // used for the ZK proof in round 5
		common.Logger.Debugf("party %v round 1 preproc, cA: %v", Pi, FormatBigInt(cA))
		round.temp.rAKI = rA
		round.temp.r7AbortData.KRandI = rA.Bytes()
	}
	return parameters, nil
}

func (round *round1) Process(*tss.ParsedMessage, *tss.PartyID, *tss.GenericParameters) *tss.Error {
	return nil
}

func (round *round1) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	Pi := round.PartyID()
	i := Pi.Index

	paiPK := round.key.PaillierPKs[i]
	kI := new(big.Int).SetBytes(round.temp.KI)
	cA := round.temp.cAKI
	rA := round.temp.rAKI

	minD := 0
	maxD := 1
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		pi, err := mta.AliceInit(paiPK, kI, cA, rA, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		r1msg1 := NewSignRound1Message1(Pj, round.PartyID(), cA, pi)
		common.Logger.Debugf("party %v round 1 postproc, Pj: %v, cA: %v, msg: %v", i, Pj,
			FormatBigInt(cA), r1msg1)
		ran := rand.Intn(maxD-minD) + minD
		ran = 0 * ran * ran
		common.Logger.Debugf("party %v round 1 I'll sleep %v seconds and send p2p msg to %v", Pi.Index, ran, j)
		time.Sleep(time.Duration(ran) * time.Second)
		round.temp.c1Is[j] = cA
		common.Logger.Debugf("party %v round 1 woke up sending p2p msg %v to %v", Pi.Index, r1msg1, j)
		round.out <- r1msg1
	}

	cmtC := parameters.Dictionary["cmt.C"].(commitments.HashCommitment)
	r1msg2 := NewSignRound1Message2(round.PartyID(), cmtC)
	ran := rand.Intn(maxD-minD) + minD
	ran = 0 * ran * ran
	common.Logger.Debugf("party %v round 1 I'll sleep %v seconds and send brdcst msg %v",
		Pi.Index, ran, r1msg2)
	time.Sleep(time.Duration(ran) * time.Second)
	common.Logger.Debugf("party %v round 1 woke up sending brdcst msg %v", Pi.Index, r1msg2)

	round.out <- r1msg2
	common.Logger.Debugf("party %v round 1 Postprocess ENDED", Pi.Index)
	round.ended = true
	return nil
}
// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index
	xi, ks, bigXs := round.key.Xi, round.key.Ks, round.key.BigXj

	// adding the key derivation delta to the xi's
	mod := common.ModInt(tss.EC().Params().N)
	xi = mod.Add(round.temp.keyDerivationDelta, xi)
	round.key.Xi = xi

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	if wI, bigWs, err := PrepareForSigning(i, len(ks), xi, ks, bigXs); err != nil {
		return err
	} else {
		round.temp.wI = wI
		round.temp.bigWs = bigWs
	}
	return nil
}

func FormatBigInt(a *big.Int) string { // TODO
	return fmt.Sprintf("0x%x", new(big.Int).Mod(a, new(big.Int).SetInt64(10000000000)))
}
