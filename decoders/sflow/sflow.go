// Package sflow decodes sFlow v5 datagrams.
package sflow

import (
	"bytes"
	"fmt"
	"math"

	"github.com/netsampler/goflow2/v2/decoders/utils"
)

// Opaque sample_data types according to https://sflow.org/SFLOW-DATAGRAM5.txt
const (
	SAMPLE_FORMAT_FLOW             = 1
	SAMPLE_FORMAT_COUNTER          = 2
	SAMPLE_FORMAT_EXPANDED_FLOW    = 3
	SAMPLE_FORMAT_EXPANDED_COUNTER = 4
	SAMPLE_FORMAT_DROP             = 5
)

// Opaque flow_data types according to https://sflow.org/SFLOW-STRUCTS5.txt
const (
	FLOW_TYPE_RAW              = 1
	FLOW_TYPE_ETH              = 2
	FLOW_TYPE_IPV4             = 3
	FLOW_TYPE_IPV6             = 4
	FLOW_TYPE_EXT_SWITCH       = 1001
	FLOW_TYPE_EXT_ROUTER       = 1002
	FLOW_TYPE_EXT_GATEWAY      = 1003
	FLOW_TYPE_EXT_USER         = 1004
	FLOW_TYPE_EXT_URL          = 1005
	FLOW_TYPE_EXT_MPLS         = 1006
	FLOW_TYPE_EXT_NAT          = 1007
	FLOW_TYPE_EXT_MPLS_TUNNEL  = 1008
	FLOW_TYPE_EXT_MPLS_VC      = 1009
	FLOW_TYPE_EXT_MPLS_FEC     = 1010
	FLOW_TYPE_EXT_MPLS_LVP_FEC = 1011
	FLOW_TYPE_EXT_VLAN_TUNNEL  = 1012

	// According to https://sflow.org/sflow_drops.txt
	FLOW_TYPE_EGRESS_QUEUE = 1036
	FLOW_TYPE_EXT_ACL      = 1037
	FLOW_TYPE_EXT_FUNCTION = 1038

	// According to https://sflow.org/sflow_host.txt
	FLOW_TYPE_EXT_SOCKET_IPV4 = 2100
	FLOW_TYPE_EXT_SOCKET_IPV6 = 2101

	// According to https://github.com/sflow/host-sflow/blob/master/src/sflow/sflow.h#L566
	FLOW_TYPE_EXT_ENTITIES = 2210
)

// Opaque counter_data types according to https://sflow.org/SFLOW-STRUCTS5.txt
const (
	COUNTER_TYPE_IF        = 1
	COUNTER_TYPE_ETH       = 2
	COUNTER_TYPE_TOKENRING = 3
	COUNTER_TYPE_VG        = 4
	COUNTER_TYPE_VLAN      = 5
	COUNTER_TYPE_CPU       = 1001
)

// Host counter types according to https://sflow.org/sflow_host.txt
const (
	COUNTER_TYPE_HOST_DESCR    = 2000
	COUNTER_TYPE_HOST_ADAPTERS = 2001
	COUNTER_TYPE_HOST_PARENT   = 2002
	COUNTER_TYPE_HOST_CPU      = 2003
	COUNTER_TYPE_HOST_MEMORY   = 2004
	COUNTER_TYPE_HOST_DISK_IO  = 2005
	COUNTER_TYPE_HOST_NET_IO   = 2006
)

// Virtual machine counter types according to https://sflow.org/sflow_host.txt
const (
	COUNTER_TYPE_VIRT_NODE    = 2100
	COUNTER_TYPE_VIRT_CPU     = 2101
	COUNTER_TYPE_VIRT_MEMORY  = 2102
	COUNTER_TYPE_VIRT_DISK_IO = 2103
	COUNTER_TYPE_VIRT_NET_IO  = 2104
)

// Machine type enumeration for host_descr
const (
	MACHINE_TYPE_UNKNOWN = 0
	MACHINE_TYPE_OTHER   = 1
	MACHINE_TYPE_X86     = 2
	MACHINE_TYPE_X86_64  = 3
	MACHINE_TYPE_IA64    = 4
	MACHINE_TYPE_SPARC   = 5
	MACHINE_TYPE_ALPHA   = 6
	MACHINE_TYPE_POWERPC = 7
	MACHINE_TYPE_M68K    = 8
	MACHINE_TYPE_MIPS    = 9
	MACHINE_TYPE_ARM     = 10
	MACHINE_TYPE_HPPA    = 11
	MACHINE_TYPE_S390    = 12
)

// OS name enumeration for host_descr
const (
	OS_NAME_UNKNOWN   = 0
	OS_NAME_OTHER     = 1
	OS_NAME_LINUX     = 2
	OS_NAME_WINDOWS   = 3
	OS_NAME_DARWIN    = 4
	OS_NAME_HPUX      = 5
	OS_NAME_AIX       = 6
	OS_NAME_DRAGONFLY = 7
	OS_NAME_FREEBSD   = 8
	OS_NAME_NETBSD    = 9
	OS_NAME_OPENBSD   = 10
	OS_NAME_OSF       = 11
	OS_NAME_SOLARIS   = 12
)

// Virtual domain state enumeration for virt_cpu
const (
	VIRT_DOMAIN_NOSTATE  = 0
	VIRT_DOMAIN_RUNNING  = 1
	VIRT_DOMAIN_BLOCKED  = 2
	VIRT_DOMAIN_PAUSED   = 3
	VIRT_DOMAIN_SHUTDOWN = 4
	VIRT_DOMAIN_SHUTOFF  = 5
	VIRT_DOMAIN_CRASHED  = 6
)

// DecoderError wraps an sFlow decode error.
type DecoderError struct {
	Err error
}

func (e *DecoderError) Error() string {
	return fmt.Sprintf("sFlow %s", e.Err.Error())
}

func (e *DecoderError) Unwrap() error {
	return e.Err
}

// FlowError annotates an error with the sFlow sample format and sequence.
type FlowError struct {
	Format uint32
	Seq    uint32
	Err    error
}

func (e *FlowError) Error() string {
	return fmt.Sprintf("[format:%d seq:%d] %s", e.Format, e.Seq, e.Err.Error())
}

func (e *FlowError) Unwrap() error {
	return e.Err
}

// RecordError annotates an error with the record data format.
type RecordError struct {
	DataFormat uint32
	Err        error
}

func (e *RecordError) Error() string {
	return fmt.Sprintf("[data-format:%d] %s", e.DataFormat, e.Err.Error())
}

func (e *RecordError) Unwrap() error {
	return e.Err
}

// DecodeIP reads an sFlow IP address with version from the payload.
func DecodeIP(payload *bytes.Buffer) (uint32, []byte, error) {
	var ipVersion uint32
	if err := utils.BinaryDecoder(payload, &ipVersion); err != nil {
		return 0, nil, fmt.Errorf("DecodeIP: [%w]", err)
	}
	var ip []byte
	switch ipVersion {
	case 1:
		ip = make([]byte, 4)
	case 2:
		ip = make([]byte, 16)
	default:
		return ipVersion, ip, fmt.Errorf("DecodeIP: unknown IP version %d", ipVersion)
	}
	if payload.Len() >= len(ip) {
		if err := utils.BinaryDecoder(payload, ip); err != nil {
			return 0, nil, fmt.Errorf("DecodeIP: [%w]", err)
		}
	} else {
		return ipVersion, ip, fmt.Errorf("DecodeIP: truncated data (need %d, got %d)", len(ip), payload.Len())
	}
	return ipVersion, ip, nil
}

// DecodeFloat32 reads a 32-bit IEEE 754 float from the payload.
func DecodeFloat32(payload *bytes.Buffer) (float32, error) {
	var bits uint32
	if err := utils.BinaryDecoder(payload, &bits); err != nil {
		return 0, fmt.Errorf("DecodeFloat32: [%w]", err)
	}
	return math.Float32frombits(bits), nil
}

// DecodeHostAdapters reads a variable-length array of host adapters.
func DecodeHostAdapters(payload *bytes.Buffer) ([]HostAdapter, error) {
	var count uint32
	if err := utils.BinaryDecoder(payload, &count); err != nil {
		return nil, fmt.Errorf("DecodeHostAdapters count: [%w]", err)
	}

	if count > 1000 { // protection against ddos
		return nil, fmt.Errorf("DecodeHostAdapters: adapter count %d exceeds limit", count)
	}

	adapters := make([]HostAdapter, count)
	for i := uint32(0); i < count; i++ {
		var ifIndex uint32
		if err := utils.BinaryDecoder(payload, &ifIndex); err != nil {
			return nil, fmt.Errorf("DecodeHostAdapters ifIndex[%d]: [%w]", i, err)
		}
		adapters[i].IfIndex = ifIndex

		var macCount uint32
		if err := utils.BinaryDecoder(payload, &macCount); err != nil {
			return nil, fmt.Errorf("DecodeHostAdapters macLen[%d]: [%w]", i, err)
		}
		adapters[i].MacAddressLength = macCount

		macAddress := make([]utils.MacAddress, macCount)
		adapters[i].MacAddress = macAddress

		for j := uint32(0); j < macCount; j++ {
			if err := utils.BinaryDecoder(payload, &macAddress[j]); err != nil {
				return nil, fmt.Errorf("DecodeHostAdapters macAddress[%d]: [%w]", j, err)
			}
		}
	}

	return adapters, nil
}

// DecodeCounterRecord decodes a counter record based on its data format.
func DecodeCounterRecord(header *RecordHeader, payload *bytes.Buffer) (CounterRecord, error) {
	counterRecord := CounterRecord{
		Header: *header,
	}
	switch header.DataFormat {
	case COUNTER_TYPE_IF:
		var ifCounters IfCounters
		if err := utils.BinaryDecoder(payload,
			&ifCounters.IfIndex,
			&ifCounters.IfType,
			&ifCounters.IfSpeed,
			&ifCounters.IfDirection,
			&ifCounters.IfStatus,
			&ifCounters.IfInOctets,
			&ifCounters.IfInUcastPkts,
			&ifCounters.IfInMulticastPkts,
			&ifCounters.IfInBroadcastPkts,
			&ifCounters.IfInDiscards,
			&ifCounters.IfInErrors,
			&ifCounters.IfInUnknownProtos,
			&ifCounters.IfOutOctets,
			&ifCounters.IfOutUcastPkts,
			&ifCounters.IfOutMulticastPkts,
			&ifCounters.IfOutBroadcastPkts,
			&ifCounters.IfOutDiscards,
			&ifCounters.IfOutErrors,
			&ifCounters.IfPromiscuousMode,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = ifCounters
	case COUNTER_TYPE_ETH:
		var ethernetCounters EthernetCounters
		if err := utils.BinaryDecoder(payload,
			&ethernetCounters.Dot3StatsAlignmentErrors,
			&ethernetCounters.Dot3StatsFCSErrors,
			&ethernetCounters.Dot3StatsSingleCollisionFrames,
			&ethernetCounters.Dot3StatsMultipleCollisionFrames,
			&ethernetCounters.Dot3StatsSQETestErrors,
			&ethernetCounters.Dot3StatsDeferredTransmissions,
			&ethernetCounters.Dot3StatsLateCollisions,
			&ethernetCounters.Dot3StatsExcessiveCollisions,
			&ethernetCounters.Dot3StatsInternalMacTransmitErrors,
			&ethernetCounters.Dot3StatsCarrierSenseErrors,
			&ethernetCounters.Dot3StatsFrameTooLongs,
			&ethernetCounters.Dot3StatsInternalMacReceiveErrors,
			&ethernetCounters.Dot3StatsSymbolErrors,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = ethernetCounters
	case COUNTER_TYPE_HOST_DESCR:
		hostDescr := HostDescr{
			UUID: utils.UUID{},
		}
		if err := utils.BinaryDecoder(payload, &hostDescr.Hostname); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		if err := utils.BinaryDecoder(payload, &hostDescr.UUID); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		if err := utils.BinaryDecoder(payload,
			&hostDescr.MachineType,
			&hostDescr.OSName,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		if err := utils.BinaryDecoder(payload, &hostDescr.OSRelease); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = hostDescr
	case COUNTER_TYPE_HOST_ADAPTERS:
		var hostAdapters HostAdapters
		adapters, err := DecodeHostAdapters(payload)
		if err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		hostAdapters.AdaptersLength = uint32(len(adapters))
		hostAdapters.Adapters = adapters
		counterRecord.Data = hostAdapters
	case COUNTER_TYPE_HOST_PARENT:
		var hostParent HostParent
		if err := utils.BinaryDecoder(payload,
			&hostParent.ContainerType,
			&hostParent.ContainerIndex,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = hostParent
	case COUNTER_TYPE_HOST_CPU:
		var hostCPU HostCPU
		// Load averages are float32
		var err error
		if hostCPU.LoadOne, err = DecodeFloat32(payload); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		if hostCPU.LoadFive, err = DecodeFloat32(payload); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		if hostCPU.LoadFifteen, err = DecodeFloat32(payload); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		// Remaining fields are uint32
		if err := utils.BinaryDecoder(payload,
			&hostCPU.ProcRun,
			&hostCPU.ProcTotal,
			&hostCPU.CPUNum,
			&hostCPU.CPUSpeed,
			&hostCPU.Uptime,
			&hostCPU.CPUUser,
			&hostCPU.CPUNice,
			&hostCPU.CPUSystem,
			&hostCPU.CPUIdle,
			&hostCPU.CPUWio,
			&hostCPU.CPUIntr,
			&hostCPU.CPUSintr,
			&hostCPU.Interrupts,
			&hostCPU.Contexts,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = hostCPU
	case COUNTER_TYPE_HOST_MEMORY:
		var hostMemory HostMemory
		if err := utils.BinaryDecoder(payload,
			&hostMemory.MemTotal,
			&hostMemory.MemFree,
			&hostMemory.MemShared,
			&hostMemory.MemBuffers,
			&hostMemory.MemCached,
			&hostMemory.SwapTotal,
			&hostMemory.SwapFree,
			&hostMemory.PageIn,
			&hostMemory.PageOut,
			&hostMemory.SwapIn,
			&hostMemory.SwapOut,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = hostMemory
	case COUNTER_TYPE_HOST_DISK_IO:
		var hostDiskIO HostDiskIO
		if err := utils.BinaryDecoder(payload,
			&hostDiskIO.DiskTotal,
			&hostDiskIO.DiskFree,
			&hostDiskIO.PartMaxUsed,
			&hostDiskIO.Reads,
			&hostDiskIO.BytesRead,
			&hostDiskIO.ReadTime,
			&hostDiskIO.Writes,
			&hostDiskIO.BytesWritten,
			&hostDiskIO.WriteTime,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = hostDiskIO
	case COUNTER_TYPE_HOST_NET_IO:
		var hostNetIO HostNetIO
		if err := utils.BinaryDecoder(payload,
			&hostNetIO.BytesIn,
			&hostNetIO.PacketsIn,
			&hostNetIO.ErrsIn,
			&hostNetIO.DropsIn,
			&hostNetIO.BytesOut,
			&hostNetIO.PacketsOut,
			&hostNetIO.ErrsOut,
			&hostNetIO.DropsOut,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = hostNetIO
	case COUNTER_TYPE_VIRT_NODE:
		var virtNode VirtNode
		if err := utils.BinaryDecoder(payload,
			&virtNode.Mhz,
			&virtNode.CPUs,
			&virtNode.Memory,
			&virtNode.MemoryFree,
			&virtNode.NumDomains,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = virtNode
	case COUNTER_TYPE_VIRT_CPU:
		var virtCPU VirtCPU
		if err := utils.BinaryDecoder(payload,
			&virtCPU.State,
			&virtCPU.CPUTime,
			&virtCPU.NrVirtCPU,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = virtCPU
	case COUNTER_TYPE_VIRT_MEMORY:
		var virtMemory VirtMemory
		if err := utils.BinaryDecoder(payload,
			&virtMemory.Memory,
			&virtMemory.MaxMemory,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = virtMemory
	case COUNTER_TYPE_VIRT_DISK_IO:
		var virtDiskIO VirtDiskIO
		if err := utils.BinaryDecoder(payload,
			&virtDiskIO.Capacity,
			&virtDiskIO.Allocation,
			&virtDiskIO.Available,
			&virtDiskIO.RdReq,
			&virtDiskIO.RdBytes,
			&virtDiskIO.WrReq,
			&virtDiskIO.WrBytes,
			&virtDiskIO.Errs,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = virtDiskIO
	case COUNTER_TYPE_VIRT_NET_IO:
		var virtNetIO VirtNetIO
		if err := utils.BinaryDecoder(payload,
			&virtNetIO.RxBytes,
			&virtNetIO.RxPackets,
			&virtNetIO.RxErrs,
			&virtNetIO.RxDrop,
			&virtNetIO.TxBytes,
			&virtNetIO.TxPackets,
			&virtNetIO.TxErrs,
			&virtNetIO.TxDrop,
		); err != nil {
			return counterRecord, &RecordError{header.DataFormat, err}
		}
		counterRecord.Data = virtNetIO
	default:
		var rawRecord RawRecord
		rawRecord.Data = payload.Bytes()
		counterRecord.Data = rawRecord
	}

	return counterRecord, nil
}

// DecodeFlowRecord decodes a flow record based on its data format.
func DecodeFlowRecord(header *RecordHeader, payload *bytes.Buffer) (FlowRecord, error) {
	flowRecord := FlowRecord{
		Header: *header,
	}
	var err error
	switch header.DataFormat {
	case FLOW_TYPE_RAW:
		sampledHeader := SampledHeader{}
		if err := utils.BinaryDecoder(payload,
			&sampledHeader.Protocol,
			&sampledHeader.FrameLength,
			&sampledHeader.Stripped,
			&sampledHeader.OriginalLength,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		sampledHeader.HeaderData = payload.Bytes()
		flowRecord.Data = sampledHeader
	case FLOW_TYPE_ETH:
		sampledEth := SampledEthernet{
			SrcMac: make([]byte, 6),
			DstMac: make([]byte, 6),
		}
		if err := utils.BinaryDecoder(payload,
			&sampledEth.Length,
			&sampledEth.SrcMac,
			&sampledEth.DstMac,
			&sampledEth.EthType,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = sampledEth
	case FLOW_TYPE_IPV4:
		sampledIP := SampledIPv4{
			SampledIPBase: SampledIPBase{
				SrcIP: make([]byte, 4),
				DstIP: make([]byte, 4),
			},
		}
		if err := utils.BinaryDecoder(payload,
			&sampledIP.Length,
			&sampledIP.Protocol,
			sampledIP.SrcIP,
			sampledIP.DstIP,
			&sampledIP.SrcPort,
			&sampledIP.DstPort,
			&sampledIP.TcpFlags,
			&sampledIP.Tos,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = sampledIP
	case FLOW_TYPE_IPV6:
		sampledIP := SampledIPv6{
			SampledIPBase: SampledIPBase{
				SrcIP: make([]byte, 16),
				DstIP: make([]byte, 16),
			},
		}
		if err := utils.BinaryDecoder(payload,
			&sampledIP.Length,
			&sampledIP.Protocol,
			sampledIP.SrcIP,
			sampledIP.DstIP,
			&sampledIP.SrcPort,
			&sampledIP.DstPort,
			&sampledIP.TcpFlags,
			&sampledIP.Priority,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = sampledIP
	case FLOW_TYPE_EXT_SWITCH:
		extendedSwitch := ExtendedSwitch{}
		err := utils.BinaryDecoder(payload, &extendedSwitch.SrcVlan, &extendedSwitch.SrcPriority, &extendedSwitch.DstVlan, &extendedSwitch.DstPriority)
		if err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = extendedSwitch
	case FLOW_TYPE_EXT_ROUTER:
		extendedRouter := ExtendedRouter{}
		if extendedRouter.NextHopIPVersion, extendedRouter.NextHop, err = DecodeIP(payload); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		if err := utils.BinaryDecoder(payload,
			&extendedRouter.SrcMaskLen,
			&extendedRouter.DstMaskLen,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = extendedRouter
	case FLOW_TYPE_EXT_GATEWAY:
		extendedGateway := ExtendedGateway{}
		if extendedGateway.NextHopIPVersion, extendedGateway.NextHop, err = DecodeIP(payload); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		if err := utils.BinaryDecoder(payload,
			&extendedGateway.AS,
			&extendedGateway.SrcAS,
			&extendedGateway.SrcPeerAS,
			&extendedGateway.ASDestinations,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		var asPath []uint32
		if extendedGateway.ASDestinations != 0 {
			if err := utils.BinaryDecoder(payload,
				&extendedGateway.ASPathType,
				&extendedGateway.ASPathLength,
			); err != nil {
				return flowRecord, &RecordError{header.DataFormat, err}
			}
			// protection for as-path length
			if extendedGateway.ASPathLength > 1000 {
				return flowRecord, &RecordError{header.DataFormat, fmt.Errorf("as-path length of %d seems quite large", extendedGateway.ASPathLength)}
			}
			if int(extendedGateway.ASPathLength) > payload.Len()-4 {
				return flowRecord, &RecordError{header.DataFormat, fmt.Errorf("invalid AS path length: %d", extendedGateway.ASPathLength)}
			}
			asPath = make([]uint32, extendedGateway.ASPathLength) // max size of 1000 for protection
			if len(asPath) > 0 {
				if err := utils.BinaryDecoder(payload, asPath); err != nil {
					return flowRecord, &RecordError{header.DataFormat, err}
				}
			}
		}
		extendedGateway.ASPath = asPath

		if err := utils.BinaryDecoder(payload,
			&extendedGateway.CommunitiesLength,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		// protection for communities length
		if extendedGateway.CommunitiesLength > 1000 {
			return flowRecord, &RecordError{header.DataFormat, fmt.Errorf("communities length of %d seems quite large", extendedGateway.ASPathLength)}
		}
		if int(extendedGateway.CommunitiesLength) > payload.Len()-4 {
			return flowRecord, &RecordError{header.DataFormat, fmt.Errorf("invalid communities length: %d", extendedGateway.ASPathLength)}
		}
		communities := make([]uint32, extendedGateway.CommunitiesLength) // max size of 1000 for protection
		if len(communities) > 0 {
			if err := utils.BinaryDecoder(payload, communities); err != nil {
				return flowRecord, &RecordError{header.DataFormat, err}
			}
		}
		if err := utils.BinaryDecoder(payload, &extendedGateway.LocalPref); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		extendedGateway.Communities = communities

		flowRecord.Data = extendedGateway
	case FLOW_TYPE_EGRESS_QUEUE:
		var queue EgressQueue
		if err := utils.BinaryDecoder(payload, &queue.Queue); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = queue
	case FLOW_TYPE_EXT_ACL:
		var acl ExtendedACL
		if err := utils.BinaryDecoder(payload, &acl.Number, &acl.Name, &acl.Direction); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = acl
	case FLOW_TYPE_EXT_FUNCTION:
		var function ExtendedFunction
		if err := utils.BinaryDecoder(payload, &function.Symbol); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = function
	case FLOW_TYPE_EXT_SOCKET_IPV4:
		extendedSocketIPv4 := ExtendedSocketIPv4{
			LocalIP:  make([]byte, 4),
			RemoteIP: make([]byte, 4),
		}
		if err := utils.BinaryDecoder(payload,
			&extendedSocketIPv4.Protocol,
			extendedSocketIPv4.LocalIP,
			extendedSocketIPv4.RemoteIP,
			&extendedSocketIPv4.LocalPort,
			&extendedSocketIPv4.RemotePort,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = extendedSocketIPv4
	case FLOW_TYPE_EXT_SOCKET_IPV6:
		extendedSocketIPv6 := ExtendedSocketIPv6{
			LocalIP:  make([]byte, 16),
			RemoteIP: make([]byte, 16),
		}
		if err := utils.BinaryDecoder(payload,
			&extendedSocketIPv6.Protocol,
			extendedSocketIPv6.LocalIP,
			extendedSocketIPv6.RemoteIP,
			&extendedSocketIPv6.LocalPort,
			&extendedSocketIPv6.RemotePort,
		); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = extendedSocketIPv6
	case FLOW_TYPE_EXT_ENTITIES:
		var entities ExtendedEntities
		if err := utils.BinaryDecoder(payload, &entities.SrcDSClass, &entities.SrcDSIndex, &entities.DstDSClass, &entities.DstDsIndex); err != nil {
			return flowRecord, &RecordError{header.DataFormat, err}
		}
		flowRecord.Data = entities
	default:
		var rawRecord RawRecord
		rawRecord.Data = payload.Bytes()
		flowRecord.Data = rawRecord
	}
	return flowRecord, nil
}

func DecodeSample(header *SampleHeader, payload *bytes.Buffer) (interface{}, error) {
	format := header.Format
	var sample interface{}

	if err := utils.BinaryDecoder(payload,
		&header.SampleSequenceNumber,
	); err != nil {
		return sample, fmt.Errorf("header seq [%w]", err)
	}
	seq := header.SampleSequenceNumber
	switch format {
	case SAMPLE_FORMAT_FLOW, SAMPLE_FORMAT_COUNTER:
		// Interlaced data-source format
		var sourceId uint32
		if err := utils.BinaryDecoder(payload, &sourceId); err != nil {
			return sample, &FlowError{format, seq, fmt.Errorf("header source [%w]", err)}
		}
		header.SourceIdType = sourceId >> 24
		header.SourceIdValue = sourceId & 0x00ffffff
	case SAMPLE_FORMAT_EXPANDED_FLOW, SAMPLE_FORMAT_EXPANDED_COUNTER, SAMPLE_FORMAT_DROP:
		// Explicit data-source format
		if err := utils.BinaryDecoder(payload,
			&header.SourceIdType,
			&header.SourceIdValue,
		); err != nil {
			return sample, &FlowError{format, seq, fmt.Errorf("header source [%w]", err)}
		}
	default:
		return sample, &FlowError{format, seq, fmt.Errorf("unknown format %d", format)}
	}

	var recordsCount uint32
	var flowSample FlowSample
	var counterSample CounterSample
	var expandedFlowSample ExpandedFlowSample
	var dropSample DropSample

	switch format {
	case SAMPLE_FORMAT_FLOW:
		flowSample.Header = *header
		if err := utils.BinaryDecoder(payload,
			&flowSample.SamplingRate,
			&flowSample.SamplePool,
			&flowSample.Drops,
			&flowSample.Input,
			&flowSample.Output,
			&flowSample.FlowRecordsCount,
		); err != nil {
			return sample, &FlowError{format, seq, fmt.Errorf("raw [%w]", err)}
		}
		recordsCount = flowSample.FlowRecordsCount
		if recordsCount > 1000 { // protection against ddos
			return sample, &FlowError{format, seq, fmt.Errorf("too many flow records: %d", recordsCount)}
		}
		flowSample.Records = make([]FlowRecord, recordsCount) // max size of 1000 for protection
		sample = flowSample
	case SAMPLE_FORMAT_COUNTER, SAMPLE_FORMAT_EXPANDED_COUNTER:
		counterSample.Header = *header
		if err := utils.BinaryDecoder(payload, &counterSample.CounterRecordsCount); err != nil {
			return sample, &FlowError{format, seq, fmt.Errorf("eth [%w]", err)}
		}
		recordsCount = counterSample.CounterRecordsCount
		if recordsCount > 1000 { // protection against ddos
			return sample, &FlowError{format, seq, fmt.Errorf("too many flow records: %d", recordsCount)}
		}
		counterSample.Records = make([]CounterRecord, recordsCount) // max size of 1000 for protection
		sample = counterSample
	case SAMPLE_FORMAT_EXPANDED_FLOW:
		expandedFlowSample.Header = *header
		if err := utils.BinaryDecoder(payload,
			&expandedFlowSample.SamplingRate,
			&expandedFlowSample.SamplePool,
			&expandedFlowSample.Drops,
			&expandedFlowSample.InputIfFormat,
			&expandedFlowSample.InputIfValue,
			&expandedFlowSample.OutputIfFormat,
			&expandedFlowSample.OutputIfValue,
			&expandedFlowSample.FlowRecordsCount,
		); err != nil {
			return sample, &FlowError{format, seq, fmt.Errorf("IPv4 [%w]", err)}
		}
		recordsCount = expandedFlowSample.FlowRecordsCount
		expandedFlowSample.Records = make([]FlowRecord, recordsCount)
		sample = expandedFlowSample
	case SAMPLE_FORMAT_DROP:
		dropSample.Header = *header
		if err := utils.BinaryDecoder(payload,
			&dropSample.Drops,
			&dropSample.Input,
			&dropSample.Output,
			&dropSample.Reason,
			&dropSample.FlowRecordsCount,
		); err != nil {
			return sample, &FlowError{format, seq, fmt.Errorf("raw [%w]", err)}
		}
		recordsCount = dropSample.FlowRecordsCount
		if recordsCount > 1000 { // protection against ddos
			return sample, &FlowError{format, seq, fmt.Errorf("too many flow records: %d", recordsCount)}
		}
		dropSample.Records = make([]FlowRecord, recordsCount) // max size of 1000 for protection
		sample = dropSample
	}
	for i := 0; i < int(recordsCount) && payload.Len() >= 8; i++ {
		recordHeader := RecordHeader{}
		if err := utils.BinaryDecoder(payload,
			&recordHeader.DataFormat,
			&recordHeader.Length,
		); err != nil {
			return sample, &FlowError{format, seq, fmt.Errorf("record header [%w]", err)}
		}
		if int(recordHeader.Length) > payload.Len() {
			break
		}
		recordReader := bytes.NewBuffer(payload.Next(int(recordHeader.Length)))
		switch format {
		case SAMPLE_FORMAT_FLOW:
			record, err := DecodeFlowRecord(&recordHeader, recordReader)
			if err != nil {
				return sample, &FlowError{format, seq, fmt.Errorf("record [%w]", err)}
			}
			flowSample.Records[i] = record
		case SAMPLE_FORMAT_COUNTER, SAMPLE_FORMAT_EXPANDED_COUNTER:
			record, err := DecodeCounterRecord(&recordHeader, recordReader)
			if err != nil {
				return sample, &FlowError{format, seq, fmt.Errorf("counter [%w]", err)}
			}
			counterSample.Records[i] = record
		case SAMPLE_FORMAT_EXPANDED_FLOW:
			record, err := DecodeFlowRecord(&recordHeader, recordReader)
			if err != nil {
				return sample, &FlowError{format, seq, fmt.Errorf("record [%w]", err)}
			}
			expandedFlowSample.Records[i] = record
		case SAMPLE_FORMAT_DROP:
			record, err := DecodeFlowRecord(&recordHeader, recordReader)
			if err != nil {
				return sample, &FlowError{format, seq, fmt.Errorf("record [%w]", err)}
			}
			dropSample.Records[i] = record
		}
	}
	return sample, nil
}

func DecodeMessageVersion(payload *bytes.Buffer, packetV5 *Packet) error {
	var version uint32
	if err := utils.BinaryDecoder(payload, &version); err != nil {
		return &DecoderError{err}
	}
	packetV5.Version = version

	if version != 5 {
		return &DecoderError{fmt.Errorf("unknown version %d", version)}
	}
	return DecodeMessage(payload, packetV5)
}

func DecodeMessage(payload *bytes.Buffer, packetV5 *Packet) error {
	if err := utils.BinaryDecoder(payload, &packetV5.IPVersion); err != nil {
		return &DecoderError{err}
	}
	var ip []byte
	switch packetV5.IPVersion {
	case 1:
		ip = make([]byte, 4)
		if err := utils.BinaryDecoder(payload, ip); err != nil {
			return &DecoderError{fmt.Errorf("IPv4 [%w]", err)}
		}
	case 2:
		ip = make([]byte, 16)
		if err := utils.BinaryDecoder(payload, ip); err != nil {
			return &DecoderError{fmt.Errorf("IPv6 [%w]", err)}
		}
	default:
		return &DecoderError{fmt.Errorf("unknown IP version %d", packetV5.IPVersion)}
	}

	packetV5.AgentIP = ip
	if err := utils.BinaryDecoder(payload,
		&packetV5.SubAgentId,
		&packetV5.SequenceNumber,
		&packetV5.Uptime,
		&packetV5.SamplesCount,
	); err != nil {
		return &DecoderError{err}
	}
	if packetV5.SamplesCount > 1000 {
		return &DecoderError{fmt.Errorf("too many samples: %d", packetV5.SamplesCount)}
	}

	packetV5.Samples = make([]interface{}, int(packetV5.SamplesCount)) // max size of 1000 for protection
	for i := 0; i < int(packetV5.SamplesCount) && payload.Len() >= 8; i++ {
		header := SampleHeader{}
		if err := utils.BinaryDecoder(payload, &header.Format, &header.Length); err != nil {
			return &DecoderError{fmt.Errorf("header [%w]", err)}
		}
		if int(header.Length) > payload.Len() {
			break
		}
		sampleReader := bytes.NewBuffer(payload.Next(int(header.Length)))

		sample, err := DecodeSample(&header, sampleReader)
		if err != nil {
			return &DecoderError{fmt.Errorf("sample [%w]", err)}
		} else {
			packetV5.Samples[i] = sample
		}
	}

	return nil
}
