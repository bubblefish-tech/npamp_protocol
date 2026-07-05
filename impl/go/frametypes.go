package npamp

// FrameType is a 16-bit frame type. The reserved system frame types below have the
// same meaning on every channel (draft-00 section 4.6); channel-specific frame
// types begin at 0x0100. Frame type 0x0000 is reserved and MUST NOT be used.
type FrameType uint16

const (
	FramePing          FrameType = 0x0001
	FramePong          FrameType = 0x0002
	FrameClose         FrameType = 0x0003
	FrameCloseAck      FrameType = 0x0004
	FrameError         FrameType = 0x0005
	FrameKeyUpdate     FrameType = 0x0006
	FrameKeyUpdateAck  FrameType = 0x0007
	FramePathChallenge FrameType = 0x0008
	FramePathResponse  FrameType = 0x0009
	FrameFlowUpdate    FrameType = 0x000A
)

// ChannelSpecificBase is the first channel-local frame type (draft-00 section 4.6).
const ChannelSpecificBase FrameType = 0x0100
