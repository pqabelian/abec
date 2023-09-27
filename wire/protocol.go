package wire

import (
	"fmt"
	"strconv"
	"strings"
)

// XXX pedro: we will probably need to bump this.
const (
	// ProtocolVersion is the latest protocol version this package supports.
	ProtocolVersion uint32 = 1

	/*	// FeeFilterVersion is the protocol version which added a new
		// feefilter message.
		FeeFilterVersion uint32 = 70013*/
)

// ServiceFlag identifies services supported by an abec peer.
type ServiceFlag uint64

const (
	// SFNodeNetwork is a flag used to indicate a peer is a full node (without witness).
	SFNodeNetwork ServiceFlag = 1 << iota

	// SFNodeGetUTXO is a flag used to indicate a peer supports the
	// getutxos and utxos commands.
	SFNodeGetUTXO

	// SFNodeWitness is a flag used to indicate a peer supports blocks
	// and transactions including witness data.
	SFNodeWitness

	// SFNodeTypeBit1 and SFNodeTypeBit2 used to indicate behavior about witness
	// SFNodeUnknown(00) represents lower version (<0.12.0) node which never prune witness
	// SFNodeFull(01) represents full node which keep all witness
	// SFNodeSemi(10) represents semi-full node which prunes witness data before last checkpoint.
	// SFNodeNormal(11) represents normal node which only keep a fixed number of witness data (MaxReservedWitness)
	SFNodeTypeBit1
	SFNodeTypeBit2
)

// NodeType is the type of node.
type NodeType uint64

const (
	UnsetNode NodeType = iota
	FullNode
	SemiFullNode
	NormalNode
)

const DefaultNodeType = NormalNode

// Map of node type back to their constant names for pretty printing.
var ntStrings = map[NodeType]string{
	UnsetNode:    "UnsetNode",
	FullNode:     "FullNode",
	SemiFullNode: "SemiFullNode",
	NormalNode:   "NormalNode",
}

// String returns the NodeType in human-readable form.
func (n NodeType) String() string {
	res, ok := ntStrings[n]
	if !ok {
		return "Unknown"
	}
	return res
}

func (n NodeType) IsUnsetNode() bool {
	return n == UnsetNode
}

func (n NodeType) IsFullNode() bool {
	return n == FullNode
}

func (n NodeType) IsSemifullNode() bool {
	return n == SemiFullNode
}

func (n NodeType) IsNormalNode() bool {
	return n == NormalNode
}

// Map of service flags back to their constant names for pretty printing.
var sfStrings = map[ServiceFlag]string{
	SFNodeNetwork:  "SFNodeNetwork",
	SFNodeGetUTXO:  "SFNodeGetUTXO",
	SFNodeWitness:  "SFNodeWitness",
	SFNodeTypeBit1: "SFNodeTypeBit1",
	SFNodeTypeBit2: "SFNodeTypeBit1",
}

// orderedSFStrings is an ordered list of service flags from highest to
// lowest.
var orderedSFStrings = []ServiceFlag{
	SFNodeNetwork,
	SFNodeGetUTXO,
	SFNodeWitness,
	SFNodeTypeBit1,
	SFNodeTypeBit2,
}

// String returns the ServiceFlag in human-readable form.
func (f ServiceFlag) String() string {
	// No flags are set.
	if f == 0 {
		return "0x0"
	}

	// Add individual bit flags.
	s := ""
	for _, flag := range orderedSFStrings {
		if f&flag == flag {
			s += sfStrings[flag] + "|"
			f -= flag
		}
	}

	// Add any remaining flags which aren't accounted for as hex.
	s = strings.TrimRight(s, "|")
	if f != 0 {
		s += "|0x" + strconv.FormatUint(uint64(f), 16)
	}
	s = strings.TrimLeft(s, "|")
	return s
}

// AbelianNet represents which Abelian network a message belongs to.
type AbelianNet uint32

// Constants used to indicate the message bitcoin network.  They can also be
// used to seek to the next message when a stream's state is unknown, but
// this package does not provide that functionality since it's generally a
// better idea to simply disconnect clients that are misbehaving over TCP.
const (
	//	todo(ABE):
	// MainNet represents the main bitcoin network.
	MainNet AbelianNet = 0xd9b4bef9

	// TestNet represents the regression test network.
	TestNet AbelianNet = 0xdab5bffa

	// TestNet3 represents the test network (version 3).
	TestNet3 AbelianNet = 0x0709110b

	// SimNet represents the simulation test network.
	SimNet AbelianNet = 0x12141c16
)

// bnStrings is a map of bitcoin networks back to their constant names for
// pretty printing.
var bnStrings = map[AbelianNet]string{
	MainNet:  "MainNet",
	TestNet:  "TestNet",
	TestNet3: "TestNet3",
	SimNet:   "SimNet",
}

// String returns the AbelianNet in human-readable form.
func (n AbelianNet) String() string {
	if s, ok := bnStrings[n]; ok {
		return s
	}

	return fmt.Sprintf("Unknown AbelianNet (%d)", uint32(n))
}
