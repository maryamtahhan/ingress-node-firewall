package pypcapng

import (
	"bytes"
	"encoding/json"
	"errors"
	"os/exec"

	"github.com/openshift/ingress-node-firewall/api/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"
)

const (
	debug    = "--debug"
	flush    = "--flush"
	backend  = "--backend"
	mode     = "--mode"
	dryrun   = "dryrun"
	iptables = "iptables"
	u32      = "u32"
	bpf      = "bpf"
	pypcapng = "/venv/bin/python3 /pypcap-ng/ingress_firewall.py"
	addarg   = pypcapng + " --mode iptables --backend u32 --flush"
	delcmd   = "/sbin/iptables -D INPUT -j IFW; /sbin/iptables -X IFW"
)

// IngNodeFwOffloadController structure is the object hold controls for starting
// ingress node firewall resource using pypcapng
type IngNodeFwOffloadController struct {
	// interfaces attachment objects
	mode    string
	flush   bool
	dryrun  bool
	backend string
	debug   bool
}

// NewIngNodeFwOffloadController creates new IngressNodeFirewall controller object.
func NewIngNodeFwOffloadController() (*IngNodeFwOffloadController, error) {
	// TODO make this configurable in time
	infc := &IngNodeFwOffloadController{
		debug:   true,
		flush:   false,
		dryrun:  true,
		backend: u32,
		mode:    iptables,
	}

	return infc, nil
}

// IngressNodeFwRulesOffloader adds/updates/deletes ingress node firewall rules using pypcapng.
func (infc *IngNodeFwOffloadController) IngressNodeFwRulesOffloader(
	ifaceIngressRules map[string][]v1alpha1.IngressNodeFirewallRules) error {

	jsonString, _ := json.Marshal(ifaceIngressRules)
	c := "echo '" + string(jsonString) + "' | " + addarg

	klog.Infof("Ingress node firewall: CALLING PYPCAPNG with command: %v", c)

	cmd := exec.Command("bash", "-c", c)
	//out, _ := cmd.CombinedOutput()
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil && err.Error() != "exit status 1" { // exit status 1 means no prog to unload
		klog.Errorf("Error offloading rule to pypcap-ng: %v", err)
		klog.Infof("PYPCAPNG output: \n %v", out.String())
		return errors.New("Error offloading rule to pypcap-ng")
	}

	klog.Infof("Ingress node firewall: PYPCAPNG SUCCESS output: \n %v", out.String())

	return nil
}

// IngressNodeFwFlush cleansup all rules offloaded by pypcapng
func (infc *IngNodeFwOffloadController) IngressNodeFwFlush(interfaceNames ...string) error {
	var errors []error

	klog.Info("IngressNodeFwFlush")
	// cmd := exec.Command("TODO")

	// if err := cmd.Run(); err != nil && err.Error() != "exit status 1" { // exit status 1 means no prog to unload
	// 	logging.Errorf("TODO" %v", err)
	// 			errors = append(errors, err)
	// }

	if len(errors) > 0 {
		return apierrors.NewAggregate(errors)
	}

	return nil
}

// Close Removes all rules offloaded by pypcapng.
func (infc *IngNodeFwOffloadController) Close() error {
	var errors []error

	klog.Info("Close")
	cmd := exec.Command("bash", "-c", delcmd)

	if err := cmd.Run(); err != nil && err.Error() != "exit status 1" { // exit status 1 means no prog to unload
		klog.Errorf("Error cleaning up iptables %v", err)
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return apierrors.NewAggregate(errors)
	}
	return nil
}
