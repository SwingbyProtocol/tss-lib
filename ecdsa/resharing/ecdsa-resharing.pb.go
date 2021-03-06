// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.3
// source: protob/ecdsa-resharing.proto

package resharing

import (
	common "github.com/binance-chain/tss-lib/common"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

//
// The Round 1 data is broadcast to peers of the New Committee in this message.
type DGRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EcdsaPub    *common.ECPoint `protobuf:"bytes,1,opt,name=ecdsa_pub,json=ecdsaPub,proto3" json:"ecdsa_pub,omitempty"`
	VCommitment []byte          `protobuf:"bytes,2,opt,name=v_commitment,json=vCommitment,proto3" json:"v_commitment,omitempty"`
}

func (x *DGRound1Message) Reset() {
	*x = DGRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound1Message) ProtoMessage() {}

func (x *DGRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound1Message.ProtoReflect.Descriptor instead.
func (*DGRound1Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{0}
}

func (x *DGRound1Message) GetEcdsaPub() *common.ECPoint {
	if x != nil {
		return x.EcdsaPub
	}
	return nil
}

func (x *DGRound1Message) GetVCommitment() []byte {
	if x != nil {
		return x.VCommitment
	}
	return nil
}

//
// The Round 2 data is broadcast to other peers of the New Committee in this message.
type DGRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaillierN                     []byte   `protobuf:"bytes,1,opt,name=paillier_n,json=paillierN,proto3" json:"paillier_n,omitempty"`
	PaillierProof                 [][]byte `protobuf:"bytes,2,rep,name=paillier_proof,json=paillierProof,proto3" json:"paillier_proof,omitempty"`
	AuthenticationEcdsaPublicKeyX []byte   `protobuf:"bytes,3,opt,name=authentication_ecdsa_public_key_x,json=authenticationEcdsaPublicKeyX,proto3" json:"authentication_ecdsa_public_key_x,omitempty"`
	AuthenticationEcdsaPublicKeyY []byte   `protobuf:"bytes,4,opt,name=authentication_ecdsa_public_key_y,json=authenticationEcdsaPublicKeyY,proto3" json:"authentication_ecdsa_public_key_y,omitempty"`
	AuthenticationPaillierSigR    []byte   `protobuf:"bytes,5,opt,name=authentication_paillier_sig_r,json=authenticationPaillierSigR,proto3" json:"authentication_paillier_sig_r,omitempty"`
	AuthenticationPaillierSigS    []byte   `protobuf:"bytes,6,opt,name=authentication_paillier_sig_s,json=authenticationPaillierSigS,proto3" json:"authentication_paillier_sig_s,omitempty"`
	NTilde                        []byte   `protobuf:"bytes,7,opt,name=n_tilde,json=nTilde,proto3" json:"n_tilde,omitempty"`
	H1                            []byte   `protobuf:"bytes,8,opt,name=h1,proto3" json:"h1,omitempty"`
	H2                            []byte   `protobuf:"bytes,9,opt,name=h2,proto3" json:"h2,omitempty"`
	Dlnproof_1                    [][]byte `protobuf:"bytes,10,rep,name=dlnproof_1,json=dlnproof1,proto3" json:"dlnproof_1,omitempty"`
	Dlnproof_2                    [][]byte `protobuf:"bytes,11,rep,name=dlnproof_2,json=dlnproof2,proto3" json:"dlnproof_2,omitempty"`
	ProofNSquareFree              []byte   `protobuf:"bytes,12,opt,name=proof_n_square_free,json=proofNSquareFree,proto3" json:"proof_n_square_free,omitempty"`
	RandIntProofNSquareFree       []byte   `protobuf:"bytes,13,opt,name=rand_int_proof_n_square_free,json=randIntProofNSquareFree,proto3" json:"rand_int_proof_n_square_free,omitempty"`
}

func (x *DGRound2Message1) Reset() {
	*x = DGRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound2Message1) ProtoMessage() {}

func (x *DGRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound2Message1.ProtoReflect.Descriptor instead.
func (*DGRound2Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{1}
}

func (x *DGRound2Message1) GetPaillierN() []byte {
	if x != nil {
		return x.PaillierN
	}
	return nil
}

func (x *DGRound2Message1) GetPaillierProof() [][]byte {
	if x != nil {
		return x.PaillierProof
	}
	return nil
}

func (x *DGRound2Message1) GetAuthenticationEcdsaPublicKeyX() []byte {
	if x != nil {
		return x.AuthenticationEcdsaPublicKeyX
	}
	return nil
}

func (x *DGRound2Message1) GetAuthenticationEcdsaPublicKeyY() []byte {
	if x != nil {
		return x.AuthenticationEcdsaPublicKeyY
	}
	return nil
}

func (x *DGRound2Message1) GetAuthenticationPaillierSigR() []byte {
	if x != nil {
		return x.AuthenticationPaillierSigR
	}
	return nil
}

func (x *DGRound2Message1) GetAuthenticationPaillierSigS() []byte {
	if x != nil {
		return x.AuthenticationPaillierSigS
	}
	return nil
}

func (x *DGRound2Message1) GetNTilde() []byte {
	if x != nil {
		return x.NTilde
	}
	return nil
}

func (x *DGRound2Message1) GetH1() []byte {
	if x != nil {
		return x.H1
	}
	return nil
}

func (x *DGRound2Message1) GetH2() []byte {
	if x != nil {
		return x.H2
	}
	return nil
}

func (x *DGRound2Message1) GetDlnproof_1() [][]byte {
	if x != nil {
		return x.Dlnproof_1
	}
	return nil
}

func (x *DGRound2Message1) GetDlnproof_2() [][]byte {
	if x != nil {
		return x.Dlnproof_2
	}
	return nil
}

func (x *DGRound2Message1) GetProofNSquareFree() []byte {
	if x != nil {
		return x.ProofNSquareFree
	}
	return nil
}

func (x *DGRound2Message1) GetRandIntProofNSquareFree() []byte {
	if x != nil {
		return x.RandIntProofNSquareFree
	}
	return nil
}

//
// The Round 2 "ACK" is broadcast to peers of the Old Committee in this message.
type DGRound2Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthenticationEcdsaPublicKeyX []byte `protobuf:"bytes,1,opt,name=authentication_ecdsa_public_key_x,json=authenticationEcdsaPublicKeyX,proto3" json:"authentication_ecdsa_public_key_x,omitempty"`
	AuthenticationEcdsaPublicKeyY []byte `protobuf:"bytes,2,opt,name=authentication_ecdsa_public_key_y,json=authenticationEcdsaPublicKeyY,proto3" json:"authentication_ecdsa_public_key_y,omitempty"`
}

func (x *DGRound2Message2) Reset() {
	*x = DGRound2Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound2Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound2Message2) ProtoMessage() {}

func (x *DGRound2Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound2Message2.ProtoReflect.Descriptor instead.
func (*DGRound2Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{2}
}

func (x *DGRound2Message2) GetAuthenticationEcdsaPublicKeyX() []byte {
	if x != nil {
		return x.AuthenticationEcdsaPublicKeyX
	}
	return nil
}

func (x *DGRound2Message2) GetAuthenticationEcdsaPublicKeyY() []byte {
	if x != nil {
		return x.AuthenticationEcdsaPublicKeyY
	}
	return nil
}

//
// The Round 3 data is sent to peers of the New Committee in this message.
type DGRound3Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Share                         []byte `protobuf:"bytes,1,opt,name=share,proto3" json:"share,omitempty"`
	AuthenticationEcdsaSigR       []byte `protobuf:"bytes,2,opt,name=authentication_ecdsa_sig_r,json=authenticationEcdsaSigR,proto3" json:"authentication_ecdsa_sig_r,omitempty"`
	AuthenticationEcdsaSigS       []byte `protobuf:"bytes,3,opt,name=authentication_ecdsa_sig_s,json=authenticationEcdsaSigS,proto3" json:"authentication_ecdsa_sig_s,omitempty"`
	AuthenticationEcdsaPublicKeyX []byte `protobuf:"bytes,4,opt,name=authentication_ecdsa_public_key_x,json=authenticationEcdsaPublicKeyX,proto3" json:"authentication_ecdsa_public_key_x,omitempty"`
	AuthenticationEcdsaPublicKeyY []byte `protobuf:"bytes,5,opt,name=authentication_ecdsa_public_key_y,json=authenticationEcdsaPublicKeyY,proto3" json:"authentication_ecdsa_public_key_y,omitempty"`
}

func (x *DGRound3Message1) Reset() {
	*x = DGRound3Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound3Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound3Message1) ProtoMessage() {}

func (x *DGRound3Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound3Message1.ProtoReflect.Descriptor instead.
func (*DGRound3Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{3}
}

func (x *DGRound3Message1) GetShare() []byte {
	if x != nil {
		return x.Share
	}
	return nil
}

func (x *DGRound3Message1) GetAuthenticationEcdsaSigR() []byte {
	if x != nil {
		return x.AuthenticationEcdsaSigR
	}
	return nil
}

func (x *DGRound3Message1) GetAuthenticationEcdsaSigS() []byte {
	if x != nil {
		return x.AuthenticationEcdsaSigS
	}
	return nil
}

func (x *DGRound3Message1) GetAuthenticationEcdsaPublicKeyX() []byte {
	if x != nil {
		return x.AuthenticationEcdsaPublicKeyX
	}
	return nil
}

func (x *DGRound3Message1) GetAuthenticationEcdsaPublicKeyY() []byte {
	if x != nil {
		return x.AuthenticationEcdsaPublicKeyY
	}
	return nil
}

//
// The Round 3 data is broadcast to peers of the New Committee in this message.
type DGRound3Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	VDecommitment [][]byte `protobuf:"bytes,1,rep,name=v_decommitment,json=vDecommitment,proto3" json:"v_decommitment,omitempty"`
}

func (x *DGRound3Message2) Reset() {
	*x = DGRound3Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound3Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound3Message2) ProtoMessage() {}

func (x *DGRound3Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound3Message2.ProtoReflect.Descriptor instead.
func (*DGRound3Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{4}
}

func (x *DGRound3Message2) GetVDecommitment() [][]byte {
	if x != nil {
		return x.VDecommitment
	}
	return nil
}

//
// The Round 4 "ACK" is broadcast to peers of the Old and New Committees from the New Committee in this message.
type DGRound4Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Content:
	//	*DGRound4Message_Ack
	//	*DGRound4Message_Abort
	Content isDGRound4Message_Content `protobuf_oneof:"content"`
}

func (x *DGRound4Message) Reset() {
	*x = DGRound4Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound4Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound4Message) ProtoMessage() {}

func (x *DGRound4Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound4Message.ProtoReflect.Descriptor instead.
func (*DGRound4Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{5}
}

func (m *DGRound4Message) GetContent() isDGRound4Message_Content {
	if m != nil {
		return m.Content
	}
	return nil
}

func (x *DGRound4Message) GetAck() *DGRound4Message_ACK {
	if x, ok := x.GetContent().(*DGRound4Message_Ack); ok {
		return x.Ack
	}
	return nil
}

func (x *DGRound4Message) GetAbort() *DGRound4Message_AbortData {
	if x, ok := x.GetContent().(*DGRound4Message_Abort); ok {
		return x.Abort
	}
	return nil
}

type isDGRound4Message_Content interface {
	isDGRound4Message_Content()
}

type DGRound4Message_Ack struct {
	Ack *DGRound4Message_ACK `protobuf:"bytes,1,opt,name=ack,proto3,oneof"`
}

type DGRound4Message_Abort struct {
	Abort *DGRound4Message_AbortData `protobuf:"bytes,2,opt,name=abort,proto3,oneof"`
}

func (*DGRound4Message_Ack) isDGRound4Message_Content() {}

func (*DGRound4Message_Abort) isDGRound4Message_Content() {}

type DGRound4Message_ACK struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ProofXiAlpha *common.ECPoint `protobuf:"bytes,1,opt,name=proof_xi_alpha,json=proofXiAlpha,proto3" json:"proof_xi_alpha,omitempty"`
	ProofXiT     []byte          `protobuf:"bytes,2,opt,name=proof_xi_t,json=proofXiT,proto3" json:"proof_xi_t,omitempty"`
}

func (x *DGRound4Message_ACK) Reset() {
	*x = DGRound4Message_ACK{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound4Message_ACK) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound4Message_ACK) ProtoMessage() {}

func (x *DGRound4Message_ACK) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound4Message_ACK.ProtoReflect.Descriptor instead.
func (*DGRound4Message_ACK) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{5, 0}
}

func (x *DGRound4Message_ACK) GetProofXiAlpha() *common.ECPoint {
	if x != nil {
		return x.ProofXiAlpha
	}
	return nil
}

func (x *DGRound4Message_ACK) GetProofXiT() []byte {
	if x != nil {
		return x.ProofXiT
	}
	return nil
}

type DGRound4Message_AbortData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PlaintiffParty uint32                               `protobuf:"varint,1,opt,name=plaintiff_party,json=plaintiffParty,proto3" json:"plaintiff_party,omitempty"`
	SuspiciousVsss []*common.VSSShareWithAuthSigMessage `protobuf:"bytes,2,rep,name=suspicious_vsss,json=suspiciousVsss,proto3" json:"suspicious_vsss,omitempty"`
}

func (x *DGRound4Message_AbortData) Reset() {
	*x = DGRound4Message_AbortData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DGRound4Message_AbortData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DGRound4Message_AbortData) ProtoMessage() {}

func (x *DGRound4Message_AbortData) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DGRound4Message_AbortData.ProtoReflect.Descriptor instead.
func (*DGRound4Message_AbortData) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{5, 1}
}

func (x *DGRound4Message_AbortData) GetPlaintiffParty() uint32 {
	if x != nil {
		return x.PlaintiffParty
	}
	return 0
}

func (x *DGRound4Message_AbortData) GetSuspiciousVsss() []*common.VSSShareWithAuthSigMessage {
	if x != nil {
		return x.SuspiciousVsss
	}
	return nil
}

var File_protob_ecdsa_resharing_proto protoreflect.FileDescriptor

var file_protob_ecdsa_resharing_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x72,
	0x65, 0x73, 0x68, 0x61, 0x72, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x5b, 0x0a, 0x0f, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x25, 0x0a, 0x09, 0x65, 0x63, 0x64, 0x73, 0x61, 0x5f,
	0x70, 0x75, 0x62, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43, 0x50, 0x6f,
	0x69, 0x6e, 0x74, 0x52, 0x08, 0x65, 0x63, 0x64, 0x73, 0x61, 0x50, 0x75, 0x62, 0x12, 0x21, 0x0a,
	0x0c, 0x76, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x0b, 0x76, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
	0x22, 0xd7, 0x04, 0x0a, 0x10, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65,
	0x72, 0x5f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x61, 0x69, 0x6c, 0x6c,
	0x69, 0x65, 0x72, 0x4e, 0x12, 0x25, 0x0a, 0x0e, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72,
	0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x70, 0x61,
	0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x48, 0x0a, 0x21, 0x61,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x65, 0x63,
	0x64, 0x73, 0x61, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x78,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x63, 0x64, 0x73, 0x61, 0x50, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x4b, 0x65, 0x79, 0x58, 0x12, 0x48, 0x0a, 0x21, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x5f, 0x70, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x45, 0x63, 0x64, 0x73, 0x61, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x59, 0x12,
	0x41, 0x0a, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x5f, 0x72,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1a, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x53, 0x69,
	0x67, 0x52, 0x12, 0x41, 0x0a, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f, 0x73, 0x69,
	0x67, 0x5f, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1a, 0x61, 0x75, 0x74, 0x68, 0x65,
	0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65,
	0x72, 0x53, 0x69, 0x67, 0x53, 0x12, 0x17, 0x0a, 0x07, 0x6e, 0x5f, 0x74, 0x69, 0x6c, 0x64, 0x65,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x6e, 0x54, 0x69, 0x6c, 0x64, 0x65, 0x12, 0x0e,
	0x0a, 0x02, 0x68, 0x31, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x68, 0x31, 0x12, 0x0e,
	0x0a, 0x02, 0x68, 0x32, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x68, 0x32, 0x12, 0x1d,
	0x0a, 0x0a, 0x64, 0x6c, 0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x31, 0x18, 0x0a, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x09, 0x64, 0x6c, 0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x31, 0x12, 0x1d, 0x0a,
	0x0a, 0x64, 0x6c, 0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x32, 0x18, 0x0b, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x09, 0x64, 0x6c, 0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x32, 0x12, 0x2d, 0x0a, 0x13,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x6e, 0x5f, 0x73, 0x71, 0x75, 0x61, 0x72, 0x65, 0x5f, 0x66,
	0x72, 0x65, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x70, 0x72, 0x6f, 0x6f, 0x66,
	0x4e, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x46, 0x72, 0x65, 0x65, 0x12, 0x3d, 0x0a, 0x1c, 0x72,
	0x61, 0x6e, 0x64, 0x5f, 0x69, 0x6e, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x6e, 0x5f,
	0x73, 0x71, 0x75, 0x61, 0x72, 0x65, 0x5f, 0x66, 0x72, 0x65, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x17, 0x72, 0x61, 0x6e, 0x64, 0x49, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4e,
	0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x46, 0x72, 0x65, 0x65, 0x22, 0xa6, 0x01, 0x0a, 0x10, 0x44,
	0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12,
	0x48, 0x0a, 0x21, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b,
	0x65, 0x79, 0x5f, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1d, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x63, 0x64, 0x73, 0x61, 0x50,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x58, 0x12, 0x48, 0x0a, 0x21, 0x61, 0x75, 0x74,
	0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x65, 0x63, 0x64, 0x73,
	0x61, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x45, 0x63, 0x64, 0x73, 0x61, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b,
	0x65, 0x79, 0x59, 0x22, 0xb6, 0x02, 0x0a, 0x10, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x12, 0x3b,
	0x0a, 0x1a, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x5f, 0x73, 0x69, 0x67, 0x5f, 0x72, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x17, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x45, 0x63, 0x64, 0x73, 0x61, 0x53, 0x69, 0x67, 0x52, 0x12, 0x3b, 0x0a, 0x1a, 0x61,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x65, 0x63,
	0x64, 0x73, 0x61, 0x5f, 0x73, 0x69, 0x67, 0x5f, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x17, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45,
	0x63, 0x64, 0x73, 0x61, 0x53, 0x69, 0x67, 0x53, 0x12, 0x48, 0x0a, 0x21, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x65, 0x63, 0x64, 0x73, 0x61,
	0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x78, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x45, 0x63, 0x64, 0x73, 0x61, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65,
	0x79, 0x58, 0x12, 0x48, 0x0a, 0x21, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1d, 0x61,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x63, 0x64,
	0x73, 0x61, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x59, 0x22, 0x39, 0x0a, 0x10,
	0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32,
	0x12, 0x25, 0x0a, 0x0e, 0x76, 0x5f, 0x64, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x76, 0x44, 0x65, 0x63, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0xcb, 0x02, 0x0a, 0x0f, 0x44, 0x47, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x34, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x28, 0x0a, 0x03, 0x61,
	0x63, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x44, 0x47, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x34, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x41, 0x43, 0x4b, 0x48, 0x00,
	0x52, 0x03, 0x61, 0x63, 0x6b, 0x12, 0x32, 0x0a, 0x05, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x44, 0x61, 0x74, 0x61,
	0x48, 0x00, 0x52, 0x05, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x1a, 0x53, 0x0a, 0x03, 0x41, 0x43, 0x4b,
	0x12, 0x2e, 0x0a, 0x0e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x78, 0x69, 0x5f, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43, 0x50, 0x6f, 0x69,
	0x6e, 0x74, 0x52, 0x0c, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x58, 0x69, 0x41, 0x6c, 0x70, 0x68, 0x61,
	0x12, 0x1c, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x78, 0x69, 0x5f, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x58, 0x69, 0x54, 0x1a, 0x7a,
	0x0a, 0x09, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x44, 0x61, 0x74, 0x61, 0x12, 0x27, 0x0a, 0x0f, 0x70,
	0x6c, 0x61, 0x69, 0x6e, 0x74, 0x69, 0x66, 0x66, 0x5f, 0x70, 0x61, 0x72, 0x74, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x69, 0x66, 0x66, 0x50,
	0x61, 0x72, 0x74, 0x79, 0x12, 0x44, 0x0a, 0x0f, 0x73, 0x75, 0x73, 0x70, 0x69, 0x63, 0x69, 0x6f,
	0x75, 0x73, 0x5f, 0x76, 0x73, 0x73, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e,
	0x56, 0x53, 0x53, 0x53, 0x68, 0x61, 0x72, 0x65, 0x57, 0x69, 0x74, 0x68, 0x41, 0x75, 0x74, 0x68,
	0x53, 0x69, 0x67, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0e, 0x73, 0x75, 0x73, 0x70,
	0x69, 0x63, 0x69, 0x6f, 0x75, 0x73, 0x56, 0x73, 0x73, 0x73, 0x42, 0x09, 0x0a, 0x07, 0x63, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x42, 0x32, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2d, 0x63, 0x68, 0x61, 0x69,
	0x6e, 0x2f, 0x74, 0x73, 0x73, 0x2d, 0x6c, 0x69, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2f,
	0x72, 0x65, 0x73, 0x68, 0x61, 0x72, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_protob_ecdsa_resharing_proto_rawDescOnce sync.Once
	file_protob_ecdsa_resharing_proto_rawDescData = file_protob_ecdsa_resharing_proto_rawDesc
)

func file_protob_ecdsa_resharing_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_resharing_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_resharing_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_resharing_proto_rawDescData)
	})
	return file_protob_ecdsa_resharing_proto_rawDescData
}

var file_protob_ecdsa_resharing_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_protob_ecdsa_resharing_proto_goTypes = []interface{}{
	(*DGRound1Message)(nil),                   // 0: DGRound1Message
	(*DGRound2Message1)(nil),                  // 1: DGRound2Message1
	(*DGRound2Message2)(nil),                  // 2: DGRound2Message2
	(*DGRound3Message1)(nil),                  // 3: DGRound3Message1
	(*DGRound3Message2)(nil),                  // 4: DGRound3Message2
	(*DGRound4Message)(nil),                   // 5: DGRound4Message
	(*DGRound4Message_ACK)(nil),               // 6: DGRound4Message.ACK
	(*DGRound4Message_AbortData)(nil),         // 7: DGRound4Message.AbortData
	(*common.ECPoint)(nil),                    // 8: ECPoint
	(*common.VSSShareWithAuthSigMessage)(nil), // 9: VSSShareWithAuthSigMessage
}
var file_protob_ecdsa_resharing_proto_depIdxs = []int32{
	8, // 0: DGRound1Message.ecdsa_pub:type_name -> ECPoint
	6, // 1: DGRound4Message.ack:type_name -> DGRound4Message.ACK
	7, // 2: DGRound4Message.abort:type_name -> DGRound4Message.AbortData
	8, // 3: DGRound4Message.ACK.proof_xi_alpha:type_name -> ECPoint
	9, // 4: DGRound4Message.AbortData.suspicious_vsss:type_name -> VSSShareWithAuthSigMessage
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_resharing_proto_init() }
func file_protob_ecdsa_resharing_proto_init() {
	if File_protob_ecdsa_resharing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_resharing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound1Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_resharing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound2Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_resharing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound2Message2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_resharing_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound3Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_resharing_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound3Message2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_resharing_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound4Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_resharing_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound4Message_ACK); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_resharing_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DGRound4Message_AbortData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_protob_ecdsa_resharing_proto_msgTypes[5].OneofWrappers = []interface{}{
		(*DGRound4Message_Ack)(nil),
		(*DGRound4Message_Abort)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protob_ecdsa_resharing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_resharing_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_resharing_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_resharing_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_resharing_proto = out.File
	file_protob_ecdsa_resharing_proto_rawDesc = nil
	file_protob_ecdsa_resharing_proto_goTypes = nil
	file_protob_ecdsa_resharing_proto_depIdxs = nil
}
