// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"github.com/hashicorp/go-multierror"
	errors2 "github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK

	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		// both committees proceed to round 5 after receiving "ACK" messages from the new committee
		return nil
	}

	Pi := round.PartyID()
	i := Pi.Index

	// 1-3. verify paillier & dln proofs, store message pieces, ensure uniqueness of h1j, h2j
	h1H2Map := make(map[string]struct{}, len(round.temp.dgRound2Message1s)*2)
	paiProofCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s)) // who caused the error(s)
	dlnProof1FailCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s))
	dlnProof2FailCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s))
	authSignaturesFailCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s))
	wg := new(sync.WaitGroup)
	for j, msg := range round.temp.dgRound2Message1s {
		r2msg1 := msg.Content().(*DGRound2Message1)
		paillierPKj, NTildej, H1j, H2j, authEcdsaPKj, authPaillierSigj :=
			r2msg1.UnmarshalPaillierPK(),
			r2msg1.UnmarshalNTilde(),
			r2msg1.UnmarshalH1(),
			r2msg1.UnmarshalH2(),
			r2msg1.UnmarshalAuthEcdsaPK(),
			r2msg1.UnmarshalAuthPaillierSignature()

		if H1j.Cmp(H2j) == 0 {
			return round.WrapError(errors.New("h1j and h2j were equal for this party"), msg.GetFrom())
		}
		h1JHex, h2JHex := hex.EncodeToString(H1j.Bytes()), hex.EncodeToString(H2j.Bytes())
		if _, found := h1H2Map[h1JHex]; found {
			return round.WrapError(errors.New("this h1j was already used by another party"), msg.GetFrom())
		}
		if _, found := h1H2Map[h2JHex]; found {
			return round.WrapError(errors.New("this h2j was already used by another party"), msg.GetFrom())
		}
		h1H2Map[h1JHex], h1H2Map[h2JHex] = struct{}{}, struct{}{}
		wg.Add(4)
		go func(j int, msg tss.ParsedMessage, r2msg1 *DGRound2Message1) {
			if ok, err := r2msg1.UnmarshalPaillierProof().Verify(paillierPKj.N, msg.GetFrom().KeyInt(), round.save.ECDSAPub); err != nil || !ok {
				paiProofCulprits[j] = msg.GetFrom()
				common.Logger.Warnf("paillier verify failed for party %s", msg.GetFrom(), err)
			}
			wg.Done()
		}(j, msg, r2msg1)
		go func(j int, msg tss.ParsedMessage, r2msg1 *DGRound2Message1, H1j, H2j, NTildej *big.Int) {
			if dlnProof1, err := r2msg1.UnmarshalDLNProof1(); err != nil || !dlnProof1.Verify(H1j, H2j, NTildej) {
				dlnProof1FailCulprits[j] = msg.GetFrom()
				common.Logger.Warnf("dln proof 1 verify failed for party %s", msg.GetFrom(), err)
			}
			wg.Done()
		}(j, msg, r2msg1, H1j, H2j, NTildej)
		go func(j int, msg tss.ParsedMessage, r2msg1 *DGRound2Message1, H1j, H2j, NTildej *big.Int) {
			if dlnProof2, err := r2msg1.UnmarshalDLNProof2(); err != nil || !dlnProof2.Verify(H2j, H1j, NTildej) {
				dlnProof2FailCulprits[j] = msg.GetFrom()
				common.Logger.Warnf("dln proof 2 verify failed for party %s", msg.GetFrom(), err)
			}
			wg.Done()
		}(j, msg, r2msg1, H1j, H2j, NTildej)
		go func(j int, msg tss.ParsedMessage, r2msg1 *DGRound2Message1) {
			verifies := ecdsa.Verify(authEcdsaPKj, ecdsautils.HashPaillierKey(paillierPKj), authPaillierSigj.R, authPaillierSigj.S)
			if !verifies {
				authSignaturesFailCulprits[j] = msg.GetFrom()
				common.Logger.Warnf("ECDSA Paillier PK verification failed for party %s", msg.GetFrom())
			}
			wg.Done()
		}(j, msg, r2msg1)
	}
	wg.Wait()
	for _, culprit := range append(append(paiProofCulprits, dlnProof1FailCulprits...), dlnProof2FailCulprits...) {
		if culprit != nil {
			return round.WrapError(errors.New("dln proof verification failed"), culprit)
		}
	}
	// save NTilde_j, h1_j, h2_j received in NewCommitteeStep1 here
	for j, msg := range round.temp.dgRound2Message1s {
		if j == i {
			continue
		}
		r2msg1 := msg.Content().(*DGRound2Message1)
		round.save.NTildej[j] = new(big.Int).SetBytes(r2msg1.NTilde)
		round.save.H1j[j] = new(big.Int).SetBytes(r2msg1.H1)
		round.save.H2j[j] = new(big.Int).SetBytes(r2msg1.H2)
		round.save.AuthenticationPKs[j] = (*ecdsautils.MarshallableEcdsaPublicKey)(r2msg1.UnmarshalAuthEcdsaPK())
		common.Logger.Debugf("party %v %p, Pj: %v, sv pk: %v",
			Pi, Pi, j, ecdsautils.FormatEcdsaPublicKey((*ecdsa.PublicKey)(round.save.AuthenticationPKs[j])))
	}

	// 4.
	newXi := big.NewInt(0)

	// 5-13.
	type culpritTuple struct {
		Pj                      *tss.PartyID
		err                     error
		feldmanCheckFailureArgs *ecdsautils.FeldmanCheckFailureEvidence
	}
	modQ := common.ModInt(tss.EC().Params().N)
	vjc := make([][]*crypto.ECPoint, len(round.OldParties().IDs()))
	culpritTuples := make([]culpritTuple, 0, len(round.OldParties().IDs()))
	for j := 0; j <= len(vjc)-1; j++ { // P1..P_t+1. Ps are indexed from 0 here
		// 6-7.
		r1msg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
		r3msg2 := round.temp.dgRound3Message2s[j].Content().(*DGRound3Message2)
		Pj := round.OldParties().IDs()[j]
		vCj, vDj := r1msg.UnmarshalVCommitment(), r3msg2.UnmarshalVDeCommitment()

		// 6. unpack flat "v" commitment content
		vCmtDeCmt := commitments.HashCommitDecommit{C: vCj, D: vDj}
		ok, flatVs := vCmtDeCmt.DeCommit()
		if !ok || len(flatVs) != (round.NewThreshold()+1)*2 { // they're points so * 2
			culprit := culpritTuple{Pj, errors.New("de-commitment of v_j0..v_jt failed"), nil}
			culpritTuples = append(culpritTuples, culprit)
			continue
		}
		vj, err := crypto.UnFlattenECPoints(tss.EC(), flatVs)
		if err != nil {
			culprit := culpritTuple{Pj, err, nil}
			culpritTuples = append(culpritTuples, culprit)
			continue
		}
		vjc[j] = vj

		// 8.
		r3msg1 := round.temp.dgRound3Message1s[j].Content().(*DGRound3Message1)
		sharej := &vss.Share{
			Threshold: round.NewThreshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     new(big.Int).SetBytes(r3msg1.Share),
		}

		authEcdsaSignature, authEcdsaPKj := r3msg1.UnmarshalAuthEcdsaSignature(), r3msg1.UnmarshalAuthEcdsaPK()

		authEcdsaSignatureOk := ecdsa.Verify(authEcdsaPKj,
			ecdsautils.HashShare(sharej),
			authEcdsaSignature.R, authEcdsaSignature.S)

		common.Logger.Debugf(" Pj: %v, auth pk: %v, sigmaji: %v , r: %v, s: %v", Pj,
			ecdsautils.FormatEcdsaPublicKey(authEcdsaPKj),
			ecdsautils.FormatShare(*sharej),
			ecdsautils.FormatBigInt(authEcdsaSignature.R), ecdsautils.FormatBigInt(authEcdsaSignature.S))

		if !authEcdsaSignatureOk {
			culprit := culpritTuple{Pj, errors.New("ecdsa signature of VSS share for authentication failed"), nil}
			culpritTuples = append(culpritTuples, culprit)
			continue
		}

		// 10.
		if ok := sharej.Verify(round.NewThreshold(), vj) && !round.shouldTriggerAbortInFeldmanCheck(); !ok {
			evidence := ecdsautils.FeldmanCheckFailureEvidence{
				Sigmaji: sharej,
				AuthSignaturePkj: ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     authEcdsaPKj.X,
					Y:     authEcdsaPKj.Y},
				AccusedPartyj:         uint32(j),
				TheHashCommitDecommit: commitments.HashCommitDecommit{C: vCj, D: vDj},
				AuthEcdsaSignature:    authEcdsaSignature,
			}
			culprit := culpritTuple{Pj, errors.New("share from old committee did not pass Verify()"), &evidence}
			culpritTuples = append(culpritTuples, culprit)
			continue
		}

		// 13.
		newXi = new(big.Int).Add(newXi, sharej.Share)
	}

	// handling previous errors and culprits
	var multiErr error
	feldmanCheckFailures := make([]*ecdsautils.FeldmanCheckFailureEvidence, 0)
	culpritSet := make(map[*tss.PartyID]struct{})

	for _, ct := range culpritTuples {
		if ct.feldmanCheckFailureArgs == nil {
			multiErr = multierror.Append(multiErr,
				round.WrapError(ct.err, ct.Pj))
			culpritSet[ct.Pj] = struct{}{}
		} else {
			feldmanCheckFailures = append(feldmanCheckFailures, ct.feldmanCheckFailureArgs)
		}
	}
	if len(feldmanCheckFailures) > 0 {
		vssShareWithAuthSigMessages := ecdsautils.PrepareShareWithAuthSigMessages(feldmanCheckFailures, round.PartyID())
		r4msg := NewDGRound4MessageAbort(round.OldParties().IDs(), Pi, vssShareWithAuthSigMessages)
		round.temp.dgRound4Messages[i] = r4msg
		round.out <- r4msg
		return nil
	}

	uniqueCulprits := make([]*tss.PartyID, 0, len(culpritSet))
	for aCulprit := range culpritSet {
		uniqueCulprits = append(uniqueCulprits, aCulprit)
	}

	if multiErr != nil {
		return round.WrapError(multiErr, uniqueCulprits...)
	}

	// 14-17.
	var err error
	Vc := make([]*crypto.ECPoint, round.NewThreshold()+1)
	for c := 0; c <= round.NewThreshold(); c++ {
		Vc[c] = vjc[0][c]
		for j := 1; j <= len(vjc)-1; j++ {
			Vc[c], err = Vc[c].Add(vjc[j][c])
			if err != nil {
				return round.WrapError(errors2.Wrapf(err, "Vc[c].Add(vjc[j][c])"))
			}
		}
	}

	// 18.
	if !Vc[0].Equals(round.save.ECDSAPub) {
		return round.WrapError(errors.New("assertion failed: V_0 != y"), round.PartyID()) // TODO - abort broadcast?
	}

	// 21-25.
	newKs := make([]*big.Int, 0, round.NewPartyCount())
	newBigXjs := make([]*crypto.ECPoint, round.NewPartyCount())
	paiProofCulprits = make([]*tss.PartyID, 0, round.NewPartyCount()) // who caused the error(s)
	for j := 0; j < round.NewPartyCount(); j++ {
		Pj := round.NewParties().IDs()[j]
		kj := Pj.KeyInt()
		newBigXj := Vc[0]
		newKs = append(newKs, kj)
		z := new(big.Int).SetInt64(int64(1))
		for c := 1; c <= round.NewThreshold(); c++ {
			z = modQ.Mul(z, kj)
			newBigXj, err = newBigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				paiProofCulprits = append(paiProofCulprits, Pj)
			}
		}
		newBigXjs[j] = newBigXj
	}
	if len(paiProofCulprits) > 0 {
		return round.WrapError(errors2.Wrapf(err, "newBigXj.Add(Vc[c].ScalarMult(z))"), paiProofCulprits...)
	}

	round.temp.newXi = newXi
	round.temp.newKs = newKs
	round.temp.newBigXjs = newBigXjs

	// Send an "ACK" message to both committees to signal that we're ready to save our data
	r4msg := NewDGRound4MessageAck(round.OldAndNewParties(), Pi)
	round.temp.dgRound4Messages[i] = r4msg
	round.out <- r4msg

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DGRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// accept messages from new -> old&new committees
	for j, msg := range round.temp.dgRound4Messages {
		if round.newOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.newOK[j] = true
	}
	return true, nil
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}

func (round *round4) shouldTriggerAbortInFeldmanCheck() bool {
	return round.shouldTriggerAbort(ecdsautils.FeldmanCheckFailure)
}
