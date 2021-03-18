// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/dlnp"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message)(nil),
		(*KGRound2Message1)(nil),
		(*KGRound2Message2)(nil),
		(*KGRound3Message)(nil),
		(*KGRound3MessageAbortMode)(nil),
	}
)

// ----- //

func NewKGRound1Message(
	from *tss.PartyID,
	ct cmt.HashCommitment,
	paillierPK *paillier.PublicKey,
	authEcdsaPK *ecdsa.PublicKey,
	authPaillierSignature *ecdsautils.ECDSASignature,
	nTildeI, h1I, h2I, proofNSquareFree, randIntProofNSquareFree *big.Int,
	dlnProof1, dlnProof2 *dlnp.Proof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dlnProof1Bz, err := dlnProof1.Marshal()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Marshal()
	if err != nil {
		return nil, err
	}
	content := &KGRound1Message{
		Commitment:                    ct.Bytes(),
		PaillierN:                     paillierPK.N.Bytes(),
		NTilde:                        nTildeI.Bytes(),
		H1:                            h1I.Bytes(),
		H2:                            h2I.Bytes(),
		Dlnproof_1:                    dlnProof1Bz,
		Dlnproof_2:                    dlnProof2Bz,
		ProofNSquareFree:              proofNSquareFree.Bytes(),
		RandIntProofNSquareFree:       randIntProofNSquareFree.Bytes(),
		AuthenticationEcdsaPublicKeyX: authEcdsaPK.X.Bytes(),
		AuthenticationEcdsaPublicKeyY: authEcdsaPK.Y.Bytes(),
		AuthenticationPaillierSigR:    authPaillierSignature.R.Bytes(),
		AuthenticationPaillierSigS:    authPaillierSignature.S.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetCommitment()) &&
		common.NonEmptyBytes(m.GetPaillierN()) &&
		common.NonEmptyBytes(m.GetNTilde()) &&
		common.NonEmptyBytes(m.GetH1()) &&
		common.NonEmptyBytes(m.GetH2()) &&
		common.NonEmptyBytes(m.GetProofNSquareFree()) &&
		common.NonEmptyBytes(m.GetRandIntProofNSquareFree()) &&
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnp.Iterations*2)) &&
		common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnp.Iterations*2))
}

func (m *KGRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

func (m *KGRound1Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KGRound1Message) UnmarshalAuthEcdsaPK() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{X: new(big.Int).SetBytes(m.GetAuthenticationEcdsaPublicKeyX()),
		Y:     new(big.Int).SetBytes(m.GetAuthenticationEcdsaPublicKeyY()),
		Curve: tss.EC(),
	}
}

func (m *KGRound1Message) UnmarshalAuthPaillierSignature() *ecdsautils.ECDSASignature {
	return ecdsautils.NewECDSASignature(new(big.Int).SetBytes(m.GetAuthenticationPaillierSigR()),
		new(big.Int).SetBytes(m.GetAuthenticationPaillierSigS()))
}

func (m *KGRound1Message) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *KGRound1Message) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *KGRound1Message) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *KGRound1Message) UnmarshalProofNSquareFree() *big.Int {
	return new(big.Int).SetBytes(m.GetProofNSquareFree())
}

func (m *KGRound1Message) UnmarshalRandomIntProofNSquareFree() *big.Int {
	return new(big.Int).SetBytes(m.GetRandIntProofNSquareFree())
}

func (m *KGRound1Message) UnmarshalDLNProof1() (*dlnp.Proof, error) {
	return dlnp.UnmarshalProof(m.GetDlnproof_1())
}

func (m *KGRound1Message) UnmarshalDLNProof2() (*dlnp.Proof, error) {
	return dlnp.UnmarshalProof(m.GetDlnproof_2())
}

// ----- //

func NewKGRound2Message1(
	to, from *tss.PartyID,
	share *vss.Share,
	authenticationEcdsaSig *ecdsautils.ECDSASignature,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &KGRound2Message1{
		Share:                   share.Share.Bytes(),
		AuthenticationEcdsaSigR: authenticationEcdsaSig.R.Bytes(),
		AuthenticationEcdsaSigS: authenticationEcdsaSig.S.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetShare())
}

func (m *KGRound2Message1) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

func (m *KGRound2Message1) UnmarshalAuthEcdsaSignature() *ecdsautils.ECDSASignature {
	return ecdsautils.NewECDSASignature(new(big.Int).SetBytes(m.AuthenticationEcdsaSigR),
		new(big.Int).SetBytes(m.AuthenticationEcdsaSigS))
}

// ----- //

func NewKGRound2Message2(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &KGRound2Message2{
		DeCommitment: dcBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetDeCommitment())
}

func (m *KGRound2Message2) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewKGRound3Message(
	from *tss.PartyID,
	paillierProof paillier.Proof,
	zkProofxi zkp.DLogProof,

) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pfBzs := make([][]byte, len(paillierProof))
	for i := range pfBzs {
		if paillierProof[i] == nil {
			continue
		}
		pfBzs[i] = paillierProof[i].Bytes()
	}
	content := &KGRound3Message{
		PaillierProof: pfBzs,
		ProofXiAlpha:  zkProofxi.Alpha.ToProtobufPoint(),
		ProofXiT:      zkProofxi.T.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetPaillierProof(), paillier.ProofIters)
}

func (m *KGRound3Message) UnmarshalProofInts() paillier.Proof {
	var pf paillier.Proof
	proofBzs := m.GetPaillierProof()
	for i := range pf {
		pf[i] = new(big.Int).SetBytes(proofBzs[i])
	}
	return pf
}

func (m *KGRound3Message) UnmarshalXiProof() (*zkp.DLogProof, error) {
	point, err := crypto.NewECPointFromProtobuf(m.GetProofXiAlpha())
	if err != nil {
		return nil, err
	}
	return &zkp.DLogProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofXiT()),
	}, nil
}

// ----- //

func NewKGRound3MessageAbortMode(
	from *tss.PartyID,
	suspiciousVssShareWithAuthSigMessages []*common.VSSShareWithAuthSigMessage,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound3MessageAbortMode{SuspiciousVsss: suspiciousVssShareWithAuthSigMessages,
		PlaintiffParty: uint32(from.Index)}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3MessageAbortMode) ValidateBasic() bool {
	if m == nil {
		return false
	}
	for _, b := range m.GetSuspiciousVsss() {
		ok := common.NonEmptyBytes(b.GetAuthSigPk().X) &&
			common.NonEmptyBytes(b.GetAuthSigPk().Y) &&
			common.NonEmptyBytes(b.GetVssId()) &&
			common.NonEmptyBytes(b.GetVssSigma()) &&
			common.NonEmptyBytes(b.GetAuthEcdsaSignatureR()) &&
			common.NonEmptyBytes(b.GetAuthEcdsaSignatureS()) &&
			common.NonEmptyMultiBytes(b.GetDj()) &&
			common.NonEmptyBytes(b.GetCj())

		if !ok {
			return false
		}
	}
	return true
}

func (m *KGRound3MessageAbortMode) UnmarshalFeldmanCheckFailureEvidence() ([]*ecdsautils.FeldmanCheckFailureEvidence, int) {
	suspiciousVsss := m.GetSuspiciousVsss()
	feldmanCheckFailures := make([]*ecdsautils.FeldmanCheckFailureEvidence, len(suspiciousVsss))
	for n, vsss := range suspiciousVsss {
		share := vss.Share{Share: new(big.Int).SetBytes(vsss.GetVssSigma()),
			ID:        new(big.Int).SetBytes(vsss.GetVssId()),
			Threshold: int(vsss.GetVssThreshold()),
		}
		pk := ecdsa.PublicKey{X: new(big.Int).SetBytes(vsss.GetAuthSigPk().GetX()),
			Y:     new(big.Int).SetBytes(vsss.GetAuthSigPk().GetY()),
			Curve: tss.EC()}
		authEcdsaSignature := ecdsautils.ECDSASignature{R: new(big.Int).SetBytes(vsss.GetAuthEcdsaSignatureR()),
			S: new(big.Int).SetBytes(vsss.GetAuthEcdsaSignatureS())}
		var Dj = make([]*big.Int, len(vsss.GetDj()))
		Cj := new(big.Int).SetBytes(vsss.GetCj())
		for a, k := range vsss.GetDj() {
			Dj[a] = new(big.Int).SetBytes(k)
		}

		e := ecdsautils.FeldmanCheckFailureEvidence{Sigmaji: &share, AuthSignaturePkj: pk,
			AccusedPartyj:         vsss.GetAccusedParty(),
			TheHashCommitDecommit: cmt.HashCommitDecommit{C: Cj, D: Dj},
			AuthEcdsaSignature:    &authEcdsaSignature}
		feldmanCheckFailures[n] = &e
	}
	return feldmanCheckFailures, int(m.GetPlaintiffParty())
}
