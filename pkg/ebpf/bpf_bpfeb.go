// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package nodefwloader

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfBpfLpmIpKeySt struct {
	PrefixLen uint32
	U         struct {
		Ip4Data [4]uint8
		_       [12]byte
	}
}

type bpfEventHdrSt struct {
	IfId   uint16
	RuleId uint16
	Action uint8
	Fill   uint8
}

type bpfRuleStatisticsSt struct {
	Packets uint64
	Bytes   uint64
}

type bpfRuleTypeSt struct {
	RuleId   uint32
	Protocol uint8
	DstPort  uint16
	IcmpType uint8
	IcmpCode uint8
	Action   uint8
}

type bpfRulesValSt struct {
	NumRules uint32
	Rules    [100]bpfRuleTypeSt
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *bpfObjects
//     *bpfPrograms
//     *bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	IngresNodeFirewallProcess *ebpf.ProgramSpec `ebpf:"ingres_node_firewall_process"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	IngressNodeFirewallStatsMap *ebpf.MapSpec `ebpf:"ingress_node_firewall_stats_map"`
	IngressNodeFirewallTableMap *ebpf.MapSpec `ebpf:"ingress_node_firewall_table_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	IngressNodeFirewallStatsMap *ebpf.Map `ebpf:"ingress_node_firewall_stats_map"`
	IngressNodeFirewallTableMap *ebpf.Map `ebpf:"ingress_node_firewall_table_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.IngressNodeFirewallStatsMap,
		m.IngressNodeFirewallTableMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	IngresNodeFirewallProcess *ebpf.Program `ebpf:"ingres_node_firewall_process"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.IngresNodeFirewallProcess,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
