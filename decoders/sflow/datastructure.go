package sflow

import "github.com/netsampler/goflow2/v2/decoders/utils"

// SampledHeader holds raw sampled header metadata.
type SampledHeader struct {
	Protocol       uint32 `json:"protocol"`
	FrameLength    uint32 `json:"frame-length"`
	Stripped       uint32 `json:"stripped"`
	OriginalLength uint32 `json:"original-length"`
	HeaderData     []byte `json:"header-data"`
}

// SampledEthernet holds Ethernet header fields for sampled frames.
type SampledEthernet struct {
	Length  uint32           `json:"length"`
	SrcMac  utils.MacAddress `json:"src-mac"`
	DstMac  utils.MacAddress `json:"dst-mac"`
	EthType uint32           `json:"eth-type"`
}

// SampledIPBase contains shared IP header fields for sampled packets.
type SampledIPBase struct {
	Length   uint32          `json:"length"`
	Protocol uint32          `json:"protocol"`
	SrcIP    utils.IPAddress `json:"src-ip"`
	DstIP    utils.IPAddress `json:"dst-ip"`
	SrcPort  uint32          `json:"src-port"`
	DstPort  uint32          `json:"dst-port"`
	TcpFlags uint32          `json:"tcp-flags"`
}

// SampledIPv4 extends SampledIPBase with IPv4 fields.
type SampledIPv4 struct {
	SampledIPBase
	Tos uint32 `json:"tos"`
}

// SampledIPv6 extends SampledIPBase with IPv6 fields.
type SampledIPv6 struct {
	SampledIPBase
	Priority uint32 `json:"priority"`
}

// ExtendedSwitch carries VLAN and priority information.
type ExtendedSwitch struct {
	SrcVlan     uint32 `json:"src-vlan"`
	SrcPriority uint32 `json:"src-priority"`
	DstVlan     uint32 `json:"dst-vlan"`
	DstPriority uint32 `json:"dst-priority"`
}

// ExtendedRouter carries next-hop and mask metadata.
type ExtendedRouter struct {
	NextHopIPVersion uint32          `json:"next-hop-ip-version"`
	NextHop          utils.IPAddress `json:"next-hop"`
	SrcMaskLen       uint32          `json:"src-mask-len"`
	DstMaskLen       uint32          `json:"dst-mask-len"`
}

// ExtendedGateway carries BGP gateway attributes and AS paths.
type ExtendedGateway struct {
	NextHopIPVersion  uint32          `json:"next-hop-ip-version"`
	NextHop           utils.IPAddress `json:"next-hop"`
	AS                uint32          `json:"as"`
	SrcAS             uint32          `json:"src-as"`
	SrcPeerAS         uint32          `json:"src-peer-as"`
	ASDestinations    uint32          `json:"as-destinations"`
	ASPathType        uint32          `json:"as-path-type"`
	ASPathLength      uint32          `json:"as-path-length"`
	ASPath            []uint32        `json:"as-path"`
	CommunitiesLength uint32          `json:"communities-length"`
	Communities       []uint32        `json:"communities"`
	LocalPref         uint32          `json:"local-pref"`
}

// EgressQueue reports a queue identifier for drop records.
type EgressQueue struct {
	Queue uint32 `json:"queue"`
}

// ExtendedACL describes an ACL match.
type ExtendedACL struct {
	Number    uint32 `json:"number"`
	Name      string `json:"name"`
	Direction uint32 `json:"direction"` // 0:unknown, 1:ingress, 2:egress
}

// ExtendedFunction identifies a forwarding function.
type ExtendedFunction struct {
	Symbol string `json:"symbol"`
}

// IfCounters stores interface counter statistics.
type IfCounters struct {
	IfIndex            uint32 `json:"if-index"`
	IfType             uint32 `json:"if-type"`
	IfSpeed            uint64 `json:"if-speed"`
	IfDirection        uint32 `json:"if-direction"`
	IfStatus           uint32 `json:"if-status"`
	IfInOctets         uint64 `json:"if-in-octets"`
	IfInUcastPkts      uint32 `json:"if-in-ucast-pkts"`
	IfInMulticastPkts  uint32 `json:"if-in-multicast-pkts"`
	IfInBroadcastPkts  uint32 `json:"if-in-broadcast-pkts"`
	IfInDiscards       uint32 `json:"if-in-discards"`
	IfInErrors         uint32 `json:"if-in-errors"`
	IfInUnknownProtos  uint32 `json:"if-in-unknown-protos"`
	IfOutOctets        uint64 `json:"if-out-octets"`
	IfOutUcastPkts     uint32 `json:"if-out-ucast-pkts"`
	IfOutMulticastPkts uint32 `json:"if-out-multicast-pkts"`
	IfOutBroadcastPkts uint32 `json:"if-out-broadcast-pkts"`
	IfOutDiscards      uint32 `json:"if-out-discards"`
	IfOutErrors        uint32 `json:"if-out-errors"`
	IfPromiscuousMode  uint32 `json:"if-promiscuous-mode"`
}

// EthernetCounters stores Ethernet-specific counter statistics.
type EthernetCounters struct {
	Dot3StatsAlignmentErrors           uint32 `json:"dot3-stats-aligment-errors"`
	Dot3StatsFCSErrors                 uint32 `json:"dot3-stats-fcse-errors"`
	Dot3StatsSingleCollisionFrames     uint32 `json:"dot3-stats-single-collision-frames"`
	Dot3StatsMultipleCollisionFrames   uint32 `json:"dot3-stats-multiple-collision-frames"`
	Dot3StatsSQETestErrors             uint32 `json:"dot3-stats-seq-test-errors"`
	Dot3StatsDeferredTransmissions     uint32 `json:"dot3-stats-deferred-transmissions"`
	Dot3StatsLateCollisions            uint32 `json:"dot3-stats-late-collisions"`
	Dot3StatsExcessiveCollisions       uint32 `json:"dot3-stats-excessive-collisions"`
	Dot3StatsInternalMacTransmitErrors uint32 `json:"dot3-stats-internal-mac-transmit-errors"`
	Dot3StatsCarrierSenseErrors        uint32 `json:"dot3-stats-carrier-sense-errors"`
	Dot3StatsFrameTooLongs             uint32 `json:"dot3-stats-frame-too-longs"`
	Dot3StatsInternalMacReceiveErrors  uint32 `json:"dot3-stats-internal-mac-receive-errors"`
	Dot3StatsSymbolErrors              uint32 `json:"dot3-stats-symbol-errors"`
}

// RawRecord stores unparsed record bytes.
type RawRecord struct {
	Data []byte `json:"data"`
}

// HostDescr describes the host machine type and OS
type HostDescr struct {
	Hostname    string     `json:"hostname"`
	UUID        utils.UUID `json:"uuid"`
	MachineType uint32     `json:"machine-type"`
	OSName      uint32     `json:"os-name"`
	OSRelease   string     `json:"os-release"`
}

// HostAdapter represents a single network adapter.
type HostAdapter struct {
	IfIndex          uint32           `json:"if-index"`
	MacAddressLength uint32           ``
	MacAddress       utils.MacAddress `json:"mac-address"`
}

// HostAdapters contains an array of host network adapters
type HostAdapters struct {
	AdaptersLength uint32        `json:"adapters-length"`
	Adapters       []HostAdapter `json:"adapters"`
}

// HostParent identifies the container for this host
type HostParent struct {
	ContainerType  uint32 `json:"container-type"`
	ContainerIndex uint32 `json:"container-index"`
}

// HostCPU provides CPU load and utilization statistics
// Load values of -1.0 indicate unknown. Time values are in milliseconds.
type HostCPU struct {
	LoadOne     float32 `json:"load-one"`
	LoadFive    float32 `json:"load-five"`
	LoadFifteen float32 `json:"load-fifteen"`
	ProcRun     uint32  `json:"proc-run"`
	ProcTotal   uint32  `json:"proc-total"`
	CPUNum      uint32  `json:"cpu-num"`
	CPUSpeed    uint32  `json:"cpu-speed"`
	Uptime      uint32  `json:"uptime"`
	CPUUser     uint32  `json:"cpu-user"`
	CPUNice     uint32  `json:"cpu-nice"`
	CPUSystem   uint32  `json:"cpu-system"`
	CPUIdle     uint32  `json:"cpu-idle"`
	CPUWio      uint32  `json:"cpu-wio"`
	CPUIntr     uint32  `json:"cpu-intr"`
	CPUSintr    uint32  `json:"cpu-sintr"`
	Interrupts  uint32  `json:"interrupts"`
	Contexts    uint32  `json:"contexts"`
}

// HostMemory provides memory and swap usage statistics
// All memory values are in bytes. Page and swap counts are operations.
type HostMemory struct {
	MemTotal   uint64 `json:"mem-total"`
	MemFree    uint64 `json:"mem-free"`
	MemShared  uint64 `json:"mem-shared"`
	MemBuffers uint64 `json:"mem-buffers"`
	MemCached  uint64 `json:"mem-cached"`
	SwapTotal  uint64 `json:"swap-total"`
	SwapFree   uint64 `json:"swap-free"`
	PageIn     uint32 `json:"page-in"`
	PageOut    uint32 `json:"page-out"`
	SwapIn     uint32 `json:"swap-in"`
	SwapOut    uint32 `json:"swap-out"`
}

// HostDiskIO provides disk I/O statistics
// Disk sizes are in bytes, times are in milliseconds.
type HostDiskIO struct {
	DiskTotal    uint64 `json:"disk-total"`
	DiskFree     uint64 `json:"disk-free"`
	PartMaxUsed  uint32 `json:"part-max-used"` // percentage 0-100
	Reads        uint32 `json:"reads"`
	BytesRead    uint64 `json:"bytes-read"`
	ReadTime     uint32 `json:"read-time"`
	Writes       uint32 `json:"writes"`
	BytesWritten uint64 `json:"bytes-written"`
	WriteTime    uint32 `json:"write-time"`
}

// HostNetIO provides network I/O statistics
// Byte counters are 64-bit, packet/error counters are 32-bit.
type HostNetIO struct {
	BytesIn    uint64 `json:"bytes-in"`
	PacketsIn  uint32 `json:"packets-in"`
	ErrsIn     uint32 `json:"errs-in"`
	DropsIn    uint32 `json:"drops-in"`
	BytesOut   uint64 `json:"bytes-out"`
	PacketsOut uint32 `json:"packets-out"`
	ErrsOut    uint32 `json:"errs-out"`
	DropsOut   uint32 `json:"drops-out"`
}

// VirtNode describes the host for virtual machines
type VirtNode struct {
	Mhz        uint32 `json:"mhz"`
	CPUs       uint32 `json:"cpus"`
	Memory     uint64 `json:"memory"`
	MemoryFree uint64 `json:"memory-free"`
	NumDomains uint32 `json:"num-domains"`
}

// VirtCPU provides virtual machine CPU statistics
type VirtCPU struct {
	State     uint32 `json:"state"`
	CPUTime   uint32 `json:"cpu-time"`
	NrVirtCPU uint32 `json:"nr-virt-cpu"`
}

// VirtMemory provides virtual machine memory statistics
type VirtMemory struct {
	Memory    uint64 `json:"memory"`
	MaxMemory uint64 `json:"max-memory"`
}

// VirtDiskIO provides virtual machine disk I/O statistics
type VirtDiskIO struct {
	Capacity   uint64 `json:"capacity"`
	Allocation uint64 `json:"allocation"`
	Available  uint64 `json:"available"`
	RdReq      uint32 `json:"rd-req"`
	RdBytes    uint64 `json:"rd-bytes"`
	WrReq      uint32 `json:"wr-req"`
	WrBytes    uint64 `json:"wr-bytes"`
	Errs       uint32 `json:"errs"`
}

// VirtNetIO provides virtual machine network I/O statistics
type VirtNetIO struct {
	RxBytes   uint64 `json:"rx-bytes"`
	RxPackets uint32 `json:"rx-packets"`
	RxErrs    uint32 `json:"rx-errs"`
	RxDrop    uint32 `json:"rx-drop"`
	TxBytes   uint64 `json:"tx-bytes"`
	TxPackets uint32 `json:"tx-packets"`
	TxErrs    uint32 `json:"tx-errs"`
	TxDrop    uint32 `json:"tx-drop"`
}

// ExtendedSocketIPv4 provides IPv4 socket information
type ExtendedSocketIPv4 struct {
	Protocol   uint32          `json:"protocol"`
	LocalIP    utils.IPAddress `json:"local-ip"`
	RemoteIP   utils.IPAddress `json:"remote-ip"`
	LocalPort  uint32          `json:"local-port"`
	RemotePort uint32          `json:"remote-port"`
}

// ExtendedSocketIPv6 provides IPv6 socket information
type ExtendedSocketIPv6 struct {
	Protocol   uint32          `json:"protocol"`
	LocalIP    utils.IPAddress `json:"local-ip"`
	RemoteIP   utils.IPAddress `json:"remote-ip"`
	LocalPort  uint32          `json:"local-port"`
	RemotePort uint32          `json:"remote-port"`
}
