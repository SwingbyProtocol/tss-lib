// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/protobuf/proto"
)

// Used externally to update a LocalParty with a valid ParsedMessage
func ParseWireMessage(wireBytes []byte, from *PartyID, isBroadcast bool) (ParsedMessage, error) {
	wire := new(MessageWrapper)
	wire.Message = new(any.Any)
	wire.From = from.MessageWrapper_PartyID
	wire.IsBroadcast = isBroadcast
	if err := proto.Unmarshal(wireBytes, wire.Message); err != nil {
		return nil, err
	}
	return parseWrappedMessage(wire, from)
}

func parseWrappedMessage(wire *MessageWrapper, from *PartyID) (ParsedMessage, error) {
	meta := MessageRouting{
		From:        from,
		IsBroadcast: wire.IsBroadcast,
	}
	var err error
	var m proto.Message
	if m, err = wire.Message.UnmarshalNew(); err != nil {
		return nil, err
	}
	return NewMessage(meta, m.(MessageContent), wire), nil
}
