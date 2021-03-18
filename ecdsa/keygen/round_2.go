// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index

	// 6. verify dln proofs, store r1 message pieces, ensure uniqueness of h1j, h2j
	h1H2Map := make(map[string]struct{}, len(round.temp.kgRound1Messages)*2)
	authSignatures := make([]*ecdsautils.ECDSASignature, len(round.temp.kgRound1Messages))
	authSignaturesFailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	dlnProof1FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	dlnProof2FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	squareFreeProofFailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	wg := new(sync.WaitGroup)
	for j, msg := range round.temp.kgRound1Messages {
		r1msg := msg.Content().(*KGRound1Message)
		paillierPKj, H1j, H2j, NTildej, authEcdsaPKj, authPaillierSigj :=
			r1msg.UnmarshalPaillierPK(),
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalAuthEcdsaPK(),
			r1msg.UnmarshalAuthPaillierSignature()

		if H1j.Cmp(H2j) == 0 {
			return round.WrapError(errors.New("h1j and h2j were equal for this party"), msg.GetFrom())
		}
		// the H1, H2 dupe check is disabled during some benchmarking scenarios to allow reuse of pre-params
		if !round.Params().UNSAFE_KGIgnoreH1H2Dupes() {
			h1JHex, h2JHex := hex.EncodeToString(H1j.Bytes()), hex.EncodeToString(H2j.Bytes())
			if _, found := h1H2Map[h1JHex]; found {
				return round.WrapError(errors.New("this h1j was already used by another party"), msg.GetFrom())
			}
			if _, found := h1H2Map[h2JHex]; found {
				return round.WrapError(errors.New("this h2j was already used by another party"), msg.GetFrom())
			}
			h1H2Map[h1JHex], h1H2Map[h2JHex] = struct{}{}, struct{}{}
		}
		wg.Add(4)
		go func(j int, msg tss.ParsedMessage, r1msg *KGRound1Message, H1j, H2j, NTildej *big.Int) {
			if dlnProof1, err := r1msg.UnmarshalDLNProof1(); err != nil || !dlnProof1.Verify(H1j, H2j, NTildej) {
				dlnProof1FailCulprits[j] = msg.GetFrom()
			}
			wg.Done()
		}(j, msg, r1msg, H1j, H2j, NTildej)
		go func(j int, msg tss.ParsedMessage, r1msg *KGRound1Message, H1j, H2j, NTildej *big.Int) {
			if dlnProof2, err := r1msg.UnmarshalDLNProof2(); err != nil || !dlnProof2.Verify(H2j, H1j, NTildej) {
				dlnProof2FailCulprits[j] = msg.GetFrom()
			}
			wg.Done()
		}(j, msg, r1msg, H1j, H2j, NTildej)

		// Verifying the proof that Nj is square-free
		go func(j int, msg tss.ParsedMessage, r1msg *KGRound1Message, NTildej *big.Int) {
			yNj := common.ModInt(NTildej).Exp(r1msg.UnmarshalProofNSquareFree(), NTildej)
			randIntProofNSquareFreej := r1msg.UnmarshalRandomIntProofNSquareFree()

			if yNj.Cmp(randIntProofNSquareFreej) != 0 {
				squareFreeProofFailCulprits[j] = msg.GetFrom()
			}
			wg.Done()
		}(j, msg, r1msg, NTildej)

		// Verify the Paillier PK with the authentication PK and sign the share
		go func(j int, msg tss.ParsedMessage) {
			verifies := ecdsa.Verify(authEcdsaPKj, ecdsautils.HashPaillierKey(paillierPKj), authPaillierSigj.R, authPaillierSigj.S)
			if !verifies {
				authSignaturesFailCulprits[j] = msg.GetFrom()
			} else {
				r, s, err := ecdsa.Sign(rand.Reader, (*ecdsa.PrivateKey)(round.save.AuthEcdsaPrivateKey),
					ecdsautils.HashShare(round.temp.shares[j]))
				authSignatures[j] = ecdsautils.NewECDSASignature(r, s)
				if err != nil {
					authSignaturesFailCulprits[j] = msg.GetFrom()
				}
			}
			wg.Done()
		}(j, msg)
	}
	wg.Wait()
	var multiErr error
	culpritSet := make(map[*tss.PartyID]struct{})
	var culpritSetAndErrors = func(arrayCulprits []*tss.PartyID, errorMessage string) {
		for _, culprit := range arrayCulprits {
			if culprit != nil {
				multiErr = multierror.Append(multiErr,
					round.WrapError(errors.New(errorMessage), culprit))
				culpritSet[culprit] = struct{}{}
			}
		}
	}
	culpritSetAndErrors(append(dlnProof1FailCulprits, dlnProof2FailCulprits...),
		"dln proof verification failed")
	culpritSetAndErrors(squareFreeProofFailCulprits,
		"big N square-free proof verification failed")
	culpritSetAndErrors(authSignaturesFailCulprits,
		"ecdsa signature of Paillier PK for authentication failed")
	uniqueCulprits := make([]*tss.PartyID, 0, len(culpritSet))
	for aCulprit := range culpritSet {
		uniqueCulprits = append(uniqueCulprits, aCulprit)
	}

	if multiErr != nil {
		return round.WrapError(multiErr, uniqueCulprits...)
	}
	// save NTilde_j, h1_j, h2_j, ...
	for j, msg := range round.temp.kgRound1Messages {
		if j == i {
			continue
		}
		r1msg := msg.Content().(*KGRound1Message)
		paillierPK, authEcdsaPKj, H1j, H2j, NTildej, KGC :=
			r1msg.UnmarshalPaillierPK(),
			r1msg.UnmarshalAuthEcdsaPK(),
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalCommitment()
		round.save.PaillierPKs[j] = paillierPK // used in round 4
		round.save.AuthenticationPKs[j] = (*ecdsautils.MarshallableEcdsaPublicKey)(authEcdsaPKj)
		round.save.NTildej[j] = NTildej
		round.save.H1j[j], round.save.H2j[j] = H1j, H2j
		round.temp.KGCs[j] = KGC
	}

	// 5. p2p send share ij to Pj
	shares := round.temp.shares
	for j, Pj := range round.Parties().IDs() {
		r2msg1 := NewKGRound2Message1(Pj, round.PartyID(), shares[j], authSignatures[j])
		// do not send to this Pj, but store for round 3
		if j == i {
			round.temp.kgRound2Message1s[j] = r2msg1
			continue
		}
		round.temp.kgRound2Message1s[i] = r2msg1
		round.out <- r2msg1
	}

	// 7. BROADCAST de-commitments of Shamir poly*G
	r2msg2 := NewKGRound2Message2(round.PartyID(), round.temp.deCommitPolyG)
	round.temp.kgRound2Message2s[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KGRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	// guard - VERIFY de-commit for all Pj
	for j, msg := range round.temp.kgRound2Message1s {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.kgRound2Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
