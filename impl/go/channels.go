package npamp

// ChannelID is a 16-bit N-PAMP channel identifier (draft-00 section 5).
type ChannelID uint16

// Core channel registry (draft-00 section 5.1).
const (
	ChanControl     ChannelID = 0x0000
	ChanMemory      ChannelID = 0x0001
	ChanCapability  ChannelID = 0x0002
	ChanIdentity    ChannelID = 0x0003
	ChanGovernance  ChannelID = 0x0004
	ChanImmune      ChannelID = 0x0005
	ChanFederation  ChannelID = 0x0006
	ChanSettlement  ChannelID = 0x0007
	ChanCompliance  ChannelID = 0x0008
	ChanSensory     ChannelID = 0x0009
	ChanTelemetry   ChannelID = 0x000A
	ChanAudit       ChannelID = 0x000B
	ChanStream      ChannelID = 0x000C
	ChanBridge      ChannelID = 0x000D
	ChanCommerce    ChannelID = 0x000E
	ChanInteraction ChannelID = 0x000F
	ChanDiscovery   ChannelID = 0x0010
	ChanWorkflow    ChannelID = 0x0011
	ChanKnowledge   ChannelID = 0x0012
	ChanSpatial     ChannelID = 0x0013
)

var channelNames = map[ChannelID]string{
	0x0000: "Control", 0x0001: "Memory", 0x0002: "Capability", 0x0003: "Identity",
	0x0004: "Governance", 0x0005: "Immune", 0x0006: "Federation", 0x0007: "Settlement",
	0x0008: "Compliance", 0x0009: "Sensory", 0x000A: "Telemetry", 0x000B: "Audit",
	0x000C: "Stream", 0x000D: "Bridge", 0x000E: "Commerce", 0x000F: "Interaction",
	0x0010: "Discovery", 0x0011: "Workflow", 0x0012: "Knowledge", 0x0013: "Spatial",
}

// Name returns the registered channel name, or "" if the ID is not a core channel.
func (c ChannelID) Name() string { return channelNames[c] }

// Reserved reports whether c is in the reserved range 0x0014..0xFFFF (draft-00 section 8.3).
func (c ChannelID) Reserved() bool { return c >= 0x0014 }
