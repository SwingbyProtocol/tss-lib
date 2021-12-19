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

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkpaffg "github.com/binance-chain/tss-lib/crypto/zkp/affg"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkpenc "github.com/binance-chain/tss-lib/crypto/zkp/enc"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	zkpmul "github.com/binance-chain/tss-lib/crypto/zkp/mul"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data common.SignatureData

		// outbound messaging
		out         chan<- tss.Message
		end         chan<- common.SignatureData
		startRndNum int
		Aborting    bool
	}

	// localMessageStore struct {
	// 	presignRound1Messages,
	// 	presignRound2Messages,
	// 	presignRound3Messages,
	// 	signRound1Messages []tss.ParsedMessage
	// }

	localTempData struct {
		// localMessageStore
		// temp data (thrown away after sign) / round 1
		w     *big.Int
		BigWs []*crypto.ECPoint
		ki    *big.Int

		Γi                 *crypto.ECPoint
		K                  *big.Int
		G                  *big.Int
		𝜌i                 *big.Int
		𝜈i                 *big.Int
		keyDerivationDelta *big.Int

		// round 2
		𝛾i                 *big.Int
		DeltaShareBetas    []*big.Int
		DeltaShareBetaNegs []*big.Int
		DeltaMtASij        []*big.Int
		DeltaMtARij        []*big.Int
		Dji                []*big.Int
		ChiShareBetas      []*big.Int
		DeltaMtAFji        []*big.Int
		ChiMtAF            *big.Int

		// round 3
		Γ                *crypto.ECPoint
		DeltaShareAlphas []*big.Int
		ChiShareAlphas   []*big.Int
		𝛿i               *big.Int
		𝜒i               *big.Int
		Δi               *crypto.ECPoint

		// round 4
		m          *big.Int
		BigR       *crypto.ECPoint
		Rx         *big.Int
		SigmaShare *big.Int

		// msg store
		r1msgG             []*big.Int
		r1msgK             []*big.Int
		r1msg𝜓0ij          []*zkpenc.ProofEnc
		r2msgBigGammaShare []*crypto.ECPoint
		r2msgDeltaD        []*big.Int
		r2msgDeltaF        []*big.Int
		r2msgDeltaFjiPki   []*big.Int
		r2msgDeltaProof    []*zkpaffg.ProofAffg
		r2msgChiD          []*big.Int
		r2msgChiF          []*big.Int
		r2msgChiProof      []*zkpaffg.ProofAffg
		r2msgProofLogstar  []*zkplogstar.ProofLogstar
		r3msg𝛿j            []*big.Int
		r3msgΔj            []*crypto.ECPoint
		r3msgProofLogstar  []*zkplogstar.ProofLogstar
		r4msg𝜎j            []*big.Int
		r4msgAborting      []bool
		// for identification
		r5msg𝛾j   []*big.Int
		r5msgsji  []*big.Int
		r5msg𝛽ʹji []*big.Int

		r6msgH                 []*big.Int
		r6msgProofMul          []*zkpmul.ProofMul
		r6msgProofDec          []*zkpdec.ProofDec
		r6msgDeltaShareEnc     []*big.Int
		r6msgEncryptedValueSum []*big.Int
	}
)

func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- common.SignatureData,
	startRndNums ...int,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      common.SignatureData{},
		out:       out,
		end:       end,
	}
	if len(startRndNums) > 0 {
		p.startRndNum = startRndNums[0]
	} else {
		p.startRndNum = 1
	}
	// msgs init
	// p.temp.presignRound1Messages = make([]tss.ParsedMessage, partyCount)
	// p.temp.presignRound2Messages = make([]tss.ParsedMessage, partyCount)
	// p.temp.presignRound3Messages = make([]tss.ParsedMessage, partyCount)
	// p.temp.signRound1Messages = make([]tss.ParsedMessage, partyCount)
	// temp data init
	p.temp.keyDerivationDelta = keyDerivationDelta
	p.temp.m = msg
	p.temp.BigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.DeltaShareBetas = make([]*big.Int, partyCount)
	p.temp.DeltaShareBetaNegs = make([]*big.Int, partyCount)
	p.temp.DeltaMtASij = make([]*big.Int, partyCount)
	p.temp.DeltaMtARij = make([]*big.Int, partyCount)
	p.temp.Dji = make([]*big.Int, partyCount)
	p.temp.ChiShareBetas = make([]*big.Int, partyCount)
	p.temp.DeltaMtAFji = make([]*big.Int, partyCount)
	p.temp.DeltaShareAlphas = make([]*big.Int, partyCount)
	p.temp.ChiShareAlphas = make([]*big.Int, partyCount)
	// temp message data init
	p.temp.r1msgG = make([]*big.Int, partyCount)
	p.temp.r1msgK = make([]*big.Int, partyCount)
	p.temp.r1msg𝜓0ij = make([]*zkpenc.ProofEnc, partyCount)
	p.temp.r2msgBigGammaShare = make([]*crypto.ECPoint, partyCount)
	p.temp.r2msgDeltaD = make([]*big.Int, partyCount)
	p.temp.r2msgDeltaF = make([]*big.Int, partyCount)
	p.temp.r2msgDeltaFjiPki = make([]*big.Int, partyCount)
	p.temp.r2msgDeltaProof = make([]*zkpaffg.ProofAffg, partyCount)
	p.temp.r2msgChiD = make([]*big.Int, partyCount)
	p.temp.r2msgChiF = make([]*big.Int, partyCount)
	p.temp.r2msgChiProof = make([]*zkpaffg.ProofAffg, partyCount)
	p.temp.r2msgProofLogstar = make([]*zkplogstar.ProofLogstar, partyCount)
	p.temp.r3msg𝛿j = make([]*big.Int, partyCount)
	p.temp.r3msgΔj = make([]*crypto.ECPoint, partyCount)
	p.temp.r3msgProofLogstar = make([]*zkplogstar.ProofLogstar, partyCount)
	p.temp.r4msg𝜎j = make([]*big.Int, partyCount)
	p.temp.r4msgAborting = make([]bool, partyCount)
	// for identification
	p.temp.r6msgH = make([]*big.Int, partyCount)
	p.temp.r6msgProofMul = make([]*zkpmul.ProofMul, partyCount)
	p.temp.r6msgProofDec = make([]*zkpdec.ProofDec, partyCount)
	p.temp.r6msgDeltaShareEnc = make([]*big.Int, partyCount)
	p.temp.r6msgEncryptedValueSum = make([]*big.Int, partyCount)
	p.temp.r5msg𝛾j = make([]*big.Int, partyCount)
	p.temp.r5msgsji = make([]*big.Int, partyCount)
	p.temp.r5msg𝛽ʹji = make([]*big.Int, partyCount)

	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	newRound := []interface{}{newRound1, newRound2, newRound3, newRound4, newRound5, newRound6, newRound7}
	return newRound[p.startRndNum-1].(func(*tss.Parameters, *keygen.LocalPartySaveData, *common.SignatureData, *localTempData, chan<- tss.Message, chan<- common.SignatureData) tss.Round)(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) SetTempData(tempNew localTempData) {
	p.temp = tempNew
}

func (p *LocalParty) Start() *tss.Error {
	if p.startRndNum == 1 {
		return tss.BaseStart(p, TaskName, func(round tss.Round) *tss.Error {
			round1, ok := round.(*presign1)
			if !ok {
				return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
			}
			if err := round1.prepare(); err != nil {
				return round.WrapError(err)
			}
			return nil
		})
	}
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *PreSignRound1Message:
		r1msg := msg.Content().(*PreSignRound1Message)
		p.temp.r1msgG[fromPIdx] = r1msg.UnmarshalG()
		p.temp.r1msgK[fromPIdx] = r1msg.UnmarshalK()
		𝜓0ij, err := r1msg.Unmarshal𝜓0ij()
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r1msg𝜓0ij[fromPIdx] = 𝜓0ij
	case *PreSignRound2Message:
		r2msg := msg.Content().(*PreSignRound2Message)
		BigGammaShare, err := r2msg.UnmarshalBigGammaShare(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msgBigGammaShare[fromPIdx] = BigGammaShare
		p.temp.r2msgDeltaD[fromPIdx] = r2msg.UnmarshalDjiDelta()
		p.temp.r2msgDeltaF[fromPIdx] = r2msg.UnmarshalFjiDelta()
		proofDelta, err := r2msg.UnmarshalAffgProofDelta(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msgDeltaProof[fromPIdx] = proofDelta
		p.temp.r2msgChiD[fromPIdx] = r2msg.UnmarshalDjiChi()
		p.temp.r2msgChiF[fromPIdx] = r2msg.UnmarshalFjiChi()
		proofChi, err := r2msg.UnmarshalAffgProofChi(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r2msgChiProof[fromPIdx] = proofChi
	case *PreSignRound3Message:
		r3msg := msg.Content().(*PreSignRound3Message)
		p.temp.r3msg𝛿j[fromPIdx] = r3msg.UnmarshalDeltaShare()
		BigDeltaShare, err := r3msg.UnmarshalBigDeltaShare(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r3msgΔj[fromPIdx] = BigDeltaShare
		proofLogStar, err := r3msg.UnmarshalProofLogstar(p.params.EC())
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r3msgProofLogstar[fromPIdx] = proofLogStar
	case *SignRound4Message:
		r4msg := msg.Content().(*SignRound4Message)
		p.temp.r4msg𝜎j[fromPIdx] = r4msg.UnmarshalSigmaShare()
	case *SignRound4AbortingMessage:
		p.temp.r4msgAborting[fromPIdx] = true
		p.Aborting = true
	case *IdentificationPrepRound5Message:
		r5msg := msg.Content().(*IdentificationPrepRound5Message)
		p.temp.r5msg𝛾j[fromPIdx] = r5msg.UnmarshalGamma()
		p.temp.r5msgsji[fromPIdx] = r5msg.UnmarshalSji()
		p.temp.r5msg𝛽ʹji[fromPIdx] = r5msg.UnmarshalBetaNegji()
		p.Aborting = true
	case *IdentificationRound6Message:
		r6msg := msg.Content().(*IdentificationRound6Message)
		p.temp.r6msgH[fromPIdx] = r6msg.UnmarshalH()
		p.temp.r6msgDeltaShareEnc[fromPIdx] = r6msg.UnmarshalDeltaShareEnc()
		p.temp.r6msgEncryptedValueSum[fromPIdx] = r6msg.UnmarshalEncryptedValueSum()
		proofMul, err := r6msg.UnmarshalProofMul()
		if err != nil {
			return false, p.WrapError(err, msg.GetFrom())
		}
		p.temp.r6msgProofMul[fromPIdx] = proofMul
		proofDec, errD := r6msg.UnmarshalProofDec()
		if errD != nil {
			return false, p.WrapError(errD, msg.GetFrom())
		}
		p.temp.r6msgProofDec[fromPIdx] = proofDec
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
