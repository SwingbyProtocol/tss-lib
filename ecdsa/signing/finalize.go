// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	TaskNameFinalize = "signing-finalize"
)

// -----
// One Round Finalization (async/offline)
// -----

func (round *finalization) InboundQueuesToConsume() []tss.QueueFunction {
	return []tss.QueueFunction{
		{round.temp.signRound7MessagesQ, &round.temp.signRound7Messages, ProcessFinalization1Round, false},
		{round.temp.signRound1Message1sQIII, &round.temp.signRound1Message1s, ProcessFinalization2Abort, false},
	}
}

// FinalizeGetOurSigShare is called in one-round signing mode after the online rounds have finished to compute s_i.
func FinalizeGetOurSigShare(state *SignatureData, msg *big.Int) (sI *big.Int) {
	data := state.GetOneRoundData()

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	kI, rSigmaI := new(big.Int).SetBytes(data.GetKI()), new(big.Int).SetBytes(data.GetRSigmaI())
	sI = modN.Add(modN.Mul(msg, kI), rSigmaI)
	return
}

// FinalizeGetOurSigShare is called in one-round signing mode to build a final signature given others' s_i shares and a msg.
// Note: each P in otherPs should correspond with that P's s_i at the same index in otherSIs.
func FinalizeGetAndVerifyFinalSig(
	state *SignatureData,
	pk *ecdsa.PublicKey,
	msg *big.Int,
	ourP *tss.PartyID,
	ourSI *big.Int,
	otherSIs map[*tss.PartyID]*big.Int,
) (*SignatureData, *btcec.Signature, *tss.Error) {
	if len(otherSIs) == 0 {
		return nil, nil, FinalizeWrapError(errors.New("len(otherSIs) == 0"), ourP)
	}
	data := state.GetOneRoundData()
	if data.GetT() != int32(len(otherSIs)) {
		return nil, nil, FinalizeWrapError(errors.New("len(otherSIs) != T"), ourP)
	}

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	bigR, err := crypto.NewECPoint(tss.EC(),
		new(big.Int).SetBytes(data.GetBigR().GetX()),
		new(big.Int).SetBytes(data.GetBigR().GetY()))
	if err != nil {
		return nil, nil, FinalizeWrapError(err, ourP)
	}

	r, s := bigR.X(), ourSI
	culprits := make([]*tss.PartyID, 0, len(otherSIs))
	for Pj, sJ := range otherSIs {
		if Pj == nil {
			return nil, nil, FinalizeWrapError(errors.New("finalize sig, in loop: Pj is nil"), Pj)
		}
		bigRBarJBz := data.GetBigRBarJ()[Pj.Id]
		bigSJBz := data.GetBigSJ()[Pj.Id]
		if bigRBarJBz == nil || bigSJBz == nil {
			return nil, nil, FinalizeWrapError(errors.New("finalize sig, in loop: map value s_i is nil"), Pj)
		}

		// prep for identify aborts in phase 7
		bigRBarJ, err := crypto.NewECPoint(tss.EC(),
			new(big.Int).SetBytes(bigRBarJBz.GetX()),
			new(big.Int).SetBytes(bigRBarJBz.GetY()))
		if err != nil {
			culprits = append(culprits, Pj)
			continue
		}
		bigSI, err := crypto.NewECPoint(tss.EC(),
			new(big.Int).SetBytes(bigSJBz.GetX()),
			new(big.Int).SetBytes(bigSJBz.GetY()))
		if err != nil {
			culprits = append(culprits, Pj)
			continue
		}

		// identify aborts of "type 8" in phase 7
		// verify that R^S_i = Rdash_i^m * S_i^r
		bigRBarIM, bigSIR, bigRSI := bigRBarJ.ScalarMult(msg), bigSI.ScalarMult(r), bigR.ScalarMult(sJ)
		bigRBarIMBigSIR, err := bigRBarIM.Add(bigSIR)
		if err != nil || !bigRSI.Equals(bigRBarIMBigSIR) {
			culprits = append(culprits, Pj)
			continue
		}

		s = modN.Add(s, sJ)
	}
	if 0 < len(culprits) {
		return nil, nil, FinalizeWrapError(errors.New("identify abort assertion fail in phase 7"), ourP, culprits...)
	}

	// Calculate Recovery ID: It is not possible to compute the public key out of the signature itself;
	// the Recovery ID is used to enable extracting the public key from the signature.
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	recId := 0
	if bigR.X().Cmp(N) > 0 {
		recId = 2
	}
	if bigR.Y().Bit(0) != 0 {
		recId |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(N, 1)
	if s.Cmp(secp256k1halfN) > 0 {
		s.Sub(N, s)
		recId ^= 1
	}

	ok := ecdsa.Verify(pk, msg.Bytes(), r, s)
	if !ok {
		return nil, nil, FinalizeWrapError(fmt.Errorf("signature verification 1 failed"), ourP)
	}

	// save the signature for final output
	signature := new(common.ECSignature)
	signature.R, signature.S = r.Bytes(), s.Bytes()
	signature.Signature = append(r.Bytes(), s.Bytes()...)
	signature.SignatureRecovery = []byte{byte(recId)}
	signature.M = msg.Bytes()
	state.Signature = signature

	btcecSig := &btcec.Signature{R: r, S: s}
	if ok = btcecSig.Verify(msg.Bytes(), (*btcec.PublicKey)(pk)); !ok {
		return nil, nil, FinalizeWrapError(fmt.Errorf("signature verification 2 failed"), ourP)
	}

	// SECURITY: to be safe the oneRoundData is no longer needed here and reuse of `r` can compromise the key
	state.OneRoundData = nil

	return state, btcecSig, nil
}

func FinalizeWrapError(err error, victim *tss.PartyID, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskNameFinalize, 8, victim, culprits...)
}

// -----
// Full Online Finalization &
// Identify Aborts of "Type 7"
// ------
func (round *finalization) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 9
	round.started = true
	round.ended = false
	Ps := round.Parties().IDs()
	parameters := &tss.GenericParameters{Dictionary: make(map[string]interface{})}
	culprits := make([]*tss.PartyID, 0, round.PartyCount())
	parameters.Dictionary["culprits"] = culprits
	// Identifiable Abort Type 7 triggered during Phase 6 (GG20)
	common.Logger.Debugf("party %v finalization Preprocess abortingT7? %v", round.PartyID(), round.abortingT7)
	if round.abortingT7 {
		common.Logger.Infof("round 8: Abort Type 7 code path triggered")

		kIs := make([][]byte, len(Ps))
		gMus := make([][]*crypto.ECPoint, len(Ps))
		gSigmaIPfs := make([]*zkp.ECDDHProof, len(Ps))
		for i := range gMus {
			gMus[i] = make([]*crypto.ECPoint, len(Ps))
		}
		parameters.Dictionary["gMus"] = gMus
		parameters.Dictionary["gSigmaIPfs"] = gSigmaIPfs
		parameters.Dictionary["kIs"] = kIs
	} else {
		otherSIs := make(map[*tss.PartyID]*big.Int, len(Ps)-1)
		parameters.Dictionary["otherSIs"] = otherSIs
	}
	return parameters, nil
}

func ProcessFinalization1Round(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, _ *sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*finalization)
	if round.abortingT7 {
		return processFinalization1Abort(round_, msg, Pj, parameters)
	} else {
		return processFinalizationNormal(round_, msg, Pj, parameters)
	}
}

func processFinalization1Abort(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters) (*tss.GenericParameters, *tss.Error) {
	var err error
	var paiPKJ *paillier.PublicKey
	round := round_.(*finalization)
	Ps := round.Parties().IDs()
	i := round.PartyID().Index
	j := Pj.Index
	q := tss.EC().Params().N
	culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)
	kIs := parameters.Dictionary["kIs"].([][]byte)
	gSigmaIPfs := parameters.Dictionary["gSigmaIPfs"].([]*zkp.ECDDHProof)
	gMus := parameters.Dictionary["gMus"].([][]*crypto.ECPoint)
	if round.abortingT7 {
		paiPKJ = round.key.PaillierPKs[j]

		r7msgInner, ok := (*msg).Content().(*SignRound7Message).GetContent().(*SignRound7Message_Abort)
		if !ok {
			common.Logger.Warnf("party %v, Pj %v, round 8: unexpected success message while in aborting mode: %+v",
				round.PartyID(), Pj, r7msgInner)
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
			return parameters, nil
		}
		r7msg := r7msgInner.Abort

		// keep k_i and the g^sigma_i proof for later
		kIs[j] = r7msg.GetKI()
		if gSigmaIPfs[j], err = r7msg.UnmarshalSigmaIProof(); err != nil {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
			return parameters, nil
		}

		// content length sanity check
		// note: the len equivalence of each of the slices in this msg have already been checked in ValidateBasic(), so just look at the UIJ slice here
		if len(r7msg.GetMuIJ()) != len(Ps) {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
			return parameters, nil
		}

		// re-encrypt k_i to make sure it matches the one we have "on record"
		cA, err := paiPKJ.EncryptWithChosenRandomness(
			new(big.Int).SetBytes(r7msg.GetKI()),
			new(big.Int).SetBytes(r7msg.GetKRandI()))
		if err != nil {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
			return parameters, nil
		}
		parameters.Dictionary["cA"] = cA

		mus := common.ByteSlicesToBigInts(r7msg.GetMuIJ())
		muRands := common.ByteSlicesToBigInts(r7msg.GetMuRandIJ())

		// check correctness of mu_i_j
		muIJ, muRandIJ := mus[i], muRands[i]
		cB, err := paiPKJ.EncryptWithChosenRandomness(muIJ, muRandIJ)
		if err != nil || !bytes.Equal(cB.Bytes(), round.temp.c2JIs[j].Bytes()) {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
			return parameters, nil
		}
		// compute g^mu_i_j
		for k, mu := range mus {
			if k == j {
				continue
			}
			gMus[j][k] = crypto.ScalarBaseMult(tss.EC(), mu.Mod(mu, q))
		}
		parameters.Dictionary["gMus"] = gMus
	}
	return parameters, nil
}

func ProcessFinalization2Abort(round_ tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters, _ *sync.RWMutex) (*tss.GenericParameters, *tss.Error) {
	round := round_.(*finalization)
	if round.abortingT7 {
		cA := parameters.Dictionary["cA"].(*big.Int)
		culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)
		r1msg1 := (*msg).Content().(*SignRound1Message1)
		if !bytes.Equal(cA.Bytes(), r1msg1.GetC()) {
			culprits = append(culprits, Pj)
			parameters.Dictionary["culprits"] = culprits
		}
	}
	return parameters, nil
}

func processFinalizationNormal(round tss.PreprocessingRound, msg *tss.ParsedMessage, Pj *tss.PartyID, parameters *tss.GenericParameters) (*tss.GenericParameters, *tss.Error) {
	culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)
	otherSIs := parameters.Dictionary["otherSIs"].(map[*tss.PartyID]*big.Int)
	var multiErr error
	if parameters.Dictionary["multiErr"] != nil {
		multiErr = parameters.Dictionary["multiErr"].(error)
	}
	r7msgInner, ok := (*msg).Content().(*SignRound7Message).GetContent().(*SignRound7Message_SI)
	if !ok {
		culprits = append(culprits, Pj)
		multiErr = multierror.Append(multiErr, fmt.Errorf("round 8: unexpected abort message while in success mode: %v %+v",
			*msg, r7msgInner))
		parameters.Dictionary["culprits"] = culprits
		parameters.Dictionary["multiErr"] = multiErr
		return parameters, round.WrapError(multiErr, culprits...)
	}
	sI := r7msgInner.SI
	otherSIs[Pj] = new(big.Int).SetBytes(sI)
	parameters.Dictionary["otherSIs"] = otherSIs
	return parameters, nil
}

func (round *finalization) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	culprits := parameters.Dictionary["culprits"].([]*tss.PartyID)
	if round.abortingT7 {
		Ps := round.Parties().IDs()
		bigR := round.temp.rI
		gNus := make([][]*crypto.ECPoint, len(Ps))
		for j := range gNus {
			gNus[j] = make([]*crypto.ECPoint, len(Ps))
		}
		gMus := parameters.Dictionary["gMus"].([][]*crypto.ECPoint)
		gSigmaIPfs := parameters.Dictionary["gSigmaIPfs"].([]*zkp.ECDDHProof)
		kIs := parameters.Dictionary["kIs"].([][]byte)

		if 0 < len(culprits) {
			goto fail
		}
		// compute g^nu_j_i's
		for i := range Ps {
			for j := range Ps {
				if j == i {
					continue
				}
				gWJKI := round.temp.bigWs[j].ScalarMultBytes(kIs[i])
				gNus[i][j], _ = gWJKI.Sub(gMus[i][j])
			}
		}
		// compute g^sigma_i's
		for _i, P := range Ps {
			gWIMulKi := round.temp.bigWs[_i].ScalarMultBytes(kIs[_i])
			gSigmaI := gWIMulKi
			for j := range Ps {
				if j == _i {
					continue
				}
				// add sum g^mu_i_j, sum g^nu_j_i
				gMuIJ, gNuJI := gMus[_i][j], gNus[j][_i]
				gSigmaI, _ = gSigmaI.Add(gMuIJ)
				gSigmaI, _ = gSigmaI.Add(gNuJI)
			}
			bigSI, _ := crypto.NewECPointFromProtobuf(round.temp.BigSJ[P.Id])
			if !gSigmaIPfs[_i].VerifySigmaI(tss.EC(), gSigmaI, bigR, bigSI) {
				culprits = append(culprits, P)
				continue
			}
		}
	fail:
		return round.WrapError(errors.New("round 7 consistency check failed: y != bigSJ products, Type 7 identified abort, culprits known"), culprits...)
	} else {
		var multiErr error
		if parameters.Dictionary["multiErr"] != nil {
			multiErr = parameters.Dictionary["multiErr"].(error)
		}
		if 0 < len(culprits) {
			return round.WrapError(multiErr, culprits...)
		}
		ourSI := round.temp.sI
		otherSIs := parameters.Dictionary["otherSIs"].(map[*tss.PartyID]*big.Int)
		pk := &ecdsa.PublicKey{
			Curve: tss.EC(),
			X:     round.key.ECDSAPub.X(),
			Y:     round.key.ECDSAPub.Y(),
		}
		data, _, err := FinalizeGetAndVerifyFinalSig(round.data, pk, round.temp.m, round.PartyID(), ourSI, otherSIs)
		if err != nil {
			return err
		}
		round.data = data
		round.end <- round.data
		round.ended = true
		return nil
	}
}

func (round *finalization) CanProceed() bool {
	return round.started && round.ended
}

func (round *finalization) CanProcess(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound7Message).GetContent().(*SignRound7Message_Abort); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound7Message).GetContent().(*SignRound7Message_SI); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
