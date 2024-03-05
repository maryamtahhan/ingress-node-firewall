package pypcapngsyncer

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/openshift/ingress-node-firewall/api/v1alpha1"
	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	intfs "github.com/openshift/ingress-node-firewall/pkg/interfaces"
	"github.com/openshift/ingress-node-firewall/pkg/metrics"
	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/pypcapng"

	"github.com/go-logr/logr"
)

const (
	chain = "IFW"
	table = "INPUT"
)

var (
	once                         sync.Once
	instance                     PypcapngSyncer
	isValidInterfaceNameAndState = intfs.IsValidInterfaceNameAndState
)

// PypcapngSyncer TODO.
type PypcapngSyncer interface {
	SyncInterfaceIngressRules(map[string][]infv1alpha1.IngressNodeFirewallRules, bool) error
}

// GetPypcapngSyncer allocates and returns a single instance of pypcapngSingleton. If such an instance does not yet exist,
// it sets up a new one. It will do so only once. Then, it returns the instance.
func GetPypcapngSyncer(ctx context.Context, log logr.Logger, stats *metrics.Statistics, mock PypcapngSyncer) PypcapngSyncer {
	once.Do(func() {
		// Check if instace is nil. For mock tests, one can provide a custom instance.
		if mock == nil {
			instance = &pypcapngSingleton{
				ctx: ctx,
				log: log,
				//	stats:             stats,
				managedInterfaces: make(map[string]struct{}),
			}
		} else {
			instance = mock
		}
	})
	return instance
}

// pypcapngSingleton implements ebpfDaemon.
type pypcapngSingleton struct {
	ctx context.Context
	log logr.Logger
	//stats             *metrics.Statistics
	c                 *nodefwloader.IngNodeFwOffloadController
	managedInterfaces map[string]struct{}
	mu                sync.Mutex
}

// syncInterfaceIngressRules takes a map of <interfaceName>:<interfaceRules> and a boolean parameter that indicates
// if rules shall be attached to the interface or if rules shall be detached from the interface.
// If isDelete is true then all rules will be detached from all provided interfaces. In such a case, the given
// interfaceRules (if any) will be ignored.
// If isDelete is false then rules will be synchronized for each of the given interfaces.
func (p *pypcapngSingleton) SyncInterfaceIngressRules(
	ifaceIngressRules map[string][]infv1alpha1.IngressNodeFirewallRules, isDelete bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	logger := p.log.WithName("syncIngressNodeFirewallResources")
	logger.Info("Running sync operation", "InterfaceIngressRules", ifaceIngressRules, "isDelete", isDelete)

	sigc := make(chan os.Signal, 1)

	//TODO ADD stats at some stage

	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(c chan os.Signal) {
		// Wait for a SIGTERM
		<-c
		if p.c != nil {
			p.resetAll()
		}
	}(sigc)

	// Create a new manager if none exists.
	if err := p.createNewManager(); err != nil {
		return err
	}

	// For delete operations, detach all interfaces and run a cleanup, set managed interfaces and the
	// manager to empty / nil values, then return.
	if isDelete {
		return p.resetAll()
	}

	// Detach unmanaged interfaces that were previously managed.
	if err := p.detachUnmanagedInterfaces(ifaceIngressRules); err != nil {
		return err
	}

	// Attach interfaces which shall now be managed.
	if err := p.attachNewInterfaces(ifaceIngressRules); err != nil {
		return err
	}

	// Offload IngressNodeFirewall Rules (this is idempotent and will add new rules and purge rules that shouldn't exist).
	if err := p.offloadIngressNodeFirewallRules(ifaceIngressRules); err != nil {
		return err
	}
	return nil
}

// Create a new manager if none exists.
func (p *pypcapngSingleton) createNewManager() error {
	var err error
	if p.c == nil {
		p.log.Info("Creating a new pypcap-ng firewall node controller")
		if p.c, err = nodefwloader.NewIngNodeFwOffloadController(); err != nil {
			return fmt.Errorf("Failed to create nodefw controller instance, err: %q", err)
		}
	}
	return nil
}

// offloadIngressNodeFirewallRules adds, updates and deletes rules from the ruleset.
func (p *pypcapngSingleton) offloadIngressNodeFirewallRules(
	ifaceIngressRules map[string][]v1alpha1.IngressNodeFirewallRules) error {
	p.log.Info("Loading rules")
	if err := p.c.IngressNodeFwRulesOffloader(ifaceIngressRules); err != nil {
		p.log.Error(err, "Failed loading ingress firewall rules")
		return err
	}
	return nil
}

// resetAll deletes all current attachments and cleans all eBPFObjects. It then sets the ingress firewall manager
// back to nil. It also deletes all pins and removed all XDP attachments for all system interfaces.
func (p *pypcapngSingleton) resetAll() error {
	p.log.Info("Closing all objects that belong to the firewall manager")
	if err := p.c.Close(); err != nil {
		p.log.Info("Could not clean up all objects that belong to the firewall manager", "err", err)
	}

	p.managedInterfaces = make(map[string]struct{})
	p.c = nil

	return nil
}

// attachNewInterfaces attaches the eBPF program to the XDP hook of unmanaged interfaces.
func (p *pypcapngSingleton) attachNewInterfaces(ifaceIngressRules map[string][]v1alpha1.IngressNodeFirewallRules) error {
	for intf := range ifaceIngressRules {
		// First, check if the interface name is valid.
		if !isValidInterfaceNameAndState(intf) {
			p.log.Info("Fail to attach ingress firewall rules", "invalid interface", intf)
			continue
		}

		// Then, check if the interface is already managed.
		if _, ok := p.managedInterfaces[intf]; !ok {
			p.log.Info("Adding firewall interface", "intf", intf)
			p.managedInterfaces[intf] = struct{}{}
			return nil
		}
	}
	return nil
}

// detachUnmanagedInterfaces detaches any interfaces that were managed by us but that should not be managed any more.
// After this it purges all rules from the ruleset for interfaces that do not exist any more.
func (p *pypcapngSingleton) detachUnmanagedInterfaces(ifaceIngressRules map[string][]infv1alpha1.IngressNodeFirewallRules) error {
	// Detach any interfaces that were managed by us but that should not be managed any more.
	p.log.Info("Comparing currently managed interfaces against list of interfaces on system",
		"p.managedInterfaces", p.managedInterfaces)
	for intf := range p.managedInterfaces {
		if _, ok := ifaceIngressRules[intf]; !ok {
			if err := p.c.Close(); err != nil {
				p.log.Error(err, "Failed clear firewall rules")
				return err
			}
			delete(p.managedInterfaces, intf)
		}
	}
	return nil
}
