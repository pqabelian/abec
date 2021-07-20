package wire

import (
	"io"
)

// MsgPong implements the Message interface and represents an Abelian pong
// message which is used primarily to confirm that a connection is still valid
// in response to a bitcoin ping message (MsgPing).
//
// This message is to implement BIP0031.
type MsgPong struct {
	// Unique value associated with message that is used to identify
	// specific ping message.
	Nonce uint64
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// BIP0031 is implemented.
func (msg *MsgPong) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readElement(r, &msg.Nonce)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgPong) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// BIP0031 is implemented.
	return writeElement(w, msg.Nonce)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgPong) Command() string {
	return CmdPong
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgPong) MaxPayloadLength(pver uint32) uint32 {
	// BIP0031 is implemented.
	// Nonce 8 bytes.
	return uint32(8)
}

// NewMsgPong returns a new bitcoin pong message that conforms to the Message
// interface.  See MsgPong for details.
func NewMsgPong(nonce uint64) *MsgPong {
	return &MsgPong{
		Nonce: nonce,
	}
}
