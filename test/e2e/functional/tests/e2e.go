package tests

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	infmetrics "github.com/openshift/ingress-node-firewall/pkg/metrics"
	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	infwutils "github.com/openshift/ingress-node-firewall/test/e2e/ingress-node-firewall"
	"github.com/openshift/ingress-node-firewall/test/e2e/pods"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/component-base/metrics/testutil"
	goclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var OperatorNameSpace = consts.DefaultOperatorNameSpace

func init() {
	if ns := os.Getenv("OO_INSTALL_NAMESPACE"); len(ns) != 0 {
		OperatorNameSpace = ns
	}
}

var _ = Describe("Ingress Node Firewall", func() {
	Context("IngressNodeFirewall deploy", func() {
		var config *ingressnodefwv1alpha1.IngressNodeFirewallConfig
		var configCRExisted bool

		BeforeEach(func() {
			var err error
			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = infwutils.LoadIngressNodeFirewallConfigFromFile(config, consts.IngressNodeFirewallConfigCRFile)
			Expect(err).ToNot(HaveOccurred())
			config.SetNamespace(OperatorNameSpace)
			configCRExisted = true
			err = testclient.Client.Get(context.Background(), goclient.ObjectKey{Namespace: config.Namespace, Name: config.Name}, config)
			if errors.IsNotFound(err) {
				configCRExisted = false
				Expect(testclient.Client.Create(context.Background(), config)).Should(Succeed())
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		AfterEach(func() {
			if !configCRExisted {
				daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				Expect(daemonset.OwnerReferences).ToNot(BeNil())
				Expect(daemonset.OwnerReferences[0].Kind).To(Equal("IngressNodeFirewallConfig"))

				infwutils.DeleteINFConfig(config)
			}
		})

		It("should run Ingress node firewall DaemonSet", func() {
			By("checking Ingress node firewall daemonset is in running state", func() {
				Eventually(func() bool {
					daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
					if err != nil {
						return false
					}
					return daemonset.Status.DesiredNumberScheduled == daemonset.Status.NumberReady
				}, infwutils.DeployTimeout, infwutils.Interval).Should(BeTrue())

				pods, err := testclient.Client.Pods(OperatorNameSpace).List(context.Background(), metav1.ListOptions{
					LabelSelector: "component=daemon"})
				Expect(err).ToNot(HaveOccurred())

				daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				Expect(len(pods.Items)).To(Equal(int(daemonset.Status.DesiredNumberScheduled)))

				for _, pod := range pods.Items {
					Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
				}
			})
		})

		It("should run Ingress node firewall apply rules and check the actions", func() {
			By("get nodes IP addresses with matching labels and ping their IPs")
			nodes, err := testclient.Client.Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/worker"})
			Expect(err).ToNot(HaveOccurred())

			err, _ = infwutils.RunPingTest(nodes.Items)
			Expect(err).ToNot(HaveOccurred())

			By("creating ingress node firewall rules")
			rules := &ingressnodefwv1alpha1.IngressNodeFirewall{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rules1",
				},
				Spec: ingressnodefwv1alpha1.IngressNodeFirewallSpec{
					NodeSelector: map[string]string{
						"node-role.kubernetes.io/worker": "",
					},
					Ingress: []ingressnodefwv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"172.16.0.0/12"},
							FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10,
									ICMPRule: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
										ICMPType: 8,
									},
									Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP,
									Action:   ingressnodefwv1alpha1.IngressNodeFirewallDeny,
								},
								{
									Order: 20,
									ProtocolRule: &ingressnodefwv1alpha1.IngressNodeFirewallProtoRule{
										Ports: "800-900",
									},
									Protocol: ingressnodefwv1alpha1.ProtocolTypeTCP,
									Action:   ingressnodefwv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
						{
							SourceCIDRs: []string{"fc00:f853:ccd:e793::0/64"},
							FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 10,
									ICMPRule: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
										ICMPType: 128,
									},
									Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP6,
									Action:   ingressnodefwv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
					Interfaces: &[]string{
						"eth0",
					},
				},
			}
			Eventually(func() error {
				err := testclient.Client.Create(context.Background(), rules)
				return err
			}, infwutils.Timeout, infwutils.Interval).Should(Succeed())

			key := types.NamespacedName{
				Name: "rules1",
			}
			By("checking Ingress node firewall rules resource is created")
			Eventually(func() error {
				err := testclient.Client.Get(context.Background(), key, rules)
				return err
			}, infwutils.Timeout, infwutils.Interval).Should(Succeed())

			By("checking ingress node firewall nodeState resource is created")
			nodeStateList := &ingressnodefwv1alpha1.IngressNodeFirewallNodeStateList{}
			Eventually(func() bool {
				err := testclient.Client.List(context.Background(), nodeStateList)
				if err != nil {
					return false
				}
				return len(nodeStateList.Items) == len(nodes.Items)
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())

			By("checking Ingress node firewall rules deny ping packets")
			Eventually(func() bool {
				err, cnt := infwutils.RunPingTest(nodes.Items)
				if err != nil && cnt == len(infwutils.NodesIP(nodes.Items)) {
					return true
				}
				return false
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())

			By("checking ingress node firewall events are generated")
			podList, err := infwutils.GetDaemonSetPods(config.Namespace)
			Expect(err).To(BeNil())
			Expect(podList).ToNot(BeNil())
			daemonPod := &podList.Items[0]
			out, _, err := pods.ExecCommand(testclient.Client, daemonPod, "cat", consts.IngressNodeFirewallEventsLogFile)
			Expect(err).ToNot(HaveOccurred())
			Eventually(func() bool {
				for _, ip := range infwutils.NodesIP(nodes.Items) {
					if !strings.Contains(out, ip) {
						return false
					}
				}
				return true
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())

			By("checking Ingress node firewall nodeState resource is deleted")
			Eventually(func() bool {
				for _, nState := range nodeStateList.Items {
					if err := testclient.Client.Delete(context.Background(), &nState); err != nil {
						if !errors.IsNotFound(err) {
							return false
						}
					}
				}
				return true
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue(), "Failed to delete IngressNodeFirewall custom resource")

			By("checking Ingress node firewall rules resource is deleted")
			Eventually(func() bool {
				err := testclient.Client.Delete(context.Background(), rules)
				return errors.IsNotFound(err)
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue(), "Failed to delete IngressNodeFirewall custom resource")
		})
	})

	Context("Statistics", func() {
		var config *ingressnodefwv1alpha1.IngressNodeFirewallConfig
		var configCRExisted bool

		BeforeEach(func() {
			var err error
			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = infwutils.LoadIngressNodeFirewallConfigFromFile(config, consts.IngressNodeFirewallConfigCRFile)
			Expect(err).ToNot(HaveOccurred())
			config.SetNamespace(OperatorNameSpace)
			configCRExisted = true
			err = testclient.Client.Get(context.Background(), goclient.ObjectKey{Namespace: config.Namespace, Name: config.Name}, config)
			if errors.IsNotFound(err) {
				configCRExisted = false
				Expect(testclient.Client.Create(context.Background(), config)).Should(Succeed())
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		AfterEach(func() {
			if !configCRExisted {
				daemonset, err := testclient.Client.DaemonSets(config.Namespace).Get(context.Background(), consts.IngressNodeFirewallDaemonsetName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				Expect(daemonset.OwnerReferences).ToNot(BeNil())
				Expect(daemonset.OwnerReferences[0].Kind).To(Equal("IngressNodeFirewallConfig"))

				infwutils.DeleteINFConfig(config)
			}
		})

		It("should expose at least one endpoint via a daemon metrics service", func() {
			err := wait.PollImmediate(1*time.Second, 10*time.Second, func() (done bool, err error) {
				endpointSliceList, err := testclient.Client.Endpoints(OperatorNameSpace).List(context.TODO(), metav1.ListOptions{
					LabelSelector: "app=ingress-node-firewall-daemon",
				})

				if err != nil {
					return false, err
				}

				if len(endpointSliceList.Items) == 0 {
					return false, nil
				}

				totalEndpoints := 0
				for _, slice := range endpointSliceList.Items {
					totalEndpoints += len(slice.Subsets)
				}
				if totalEndpoints > 0 {
					return true, nil
				}
				return false, nil
			})

			Expect(err).Should(BeNil())
		})

		It("should expose daemon metrics", func() {
			podList, err := infwutils.GetDaemonSetPods(config.Namespace)
			Expect(err).To(BeNil())
			Expect(podList).ToNot(BeNil())
			daemonPod := &podList.Items[0]

			nodes, err := testclient.Client.Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/worker"})
			Expect(err).ToNot(HaveOccurred())

			err, _ = infwutils.RunPingTest(nodes.Items)
			Expect(err).ToNot(HaveOccurred())

			rules := &ingressnodefwv1alpha1.IngressNodeFirewall{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rules1",
				},
				Spec: ingressnodefwv1alpha1.IngressNodeFirewallSpec{
					NodeSelector: map[string]string{
						"node-role.kubernetes.io/worker": "",
					},
					Ingress: []ingressnodefwv1alpha1.IngressNodeFirewallRules{
						{
							SourceCIDRs: []string{"172.0.0.0/8"},
							FirewallProtocolRules: []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule{
								{
									Order: 1,
									ICMPRule: &ingressnodefwv1alpha1.IngressNodeFirewallICMPRule{
										ICMPType: 8,
									},
									Protocol: ingressnodefwv1alpha1.ProtocolTypeICMP,
									Action:   ingressnodefwv1alpha1.IngressNodeFirewallDeny,
								},
							},
						},
					},
					Interfaces: &[]string{
						"eth0",
					},
				},
			}

			Eventually(func() error {
				err := testclient.Client.Create(context.Background(), rules)
				return err
			}, infwutils.Timeout, infwutils.Interval).Should(Succeed())

			defer Eventually(func() bool {
				err := testclient.Client.Delete(context.Background(), rules)
				return errors.IsNotFound(err)
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue(), "Failed to delete IngressNodeFirewall custom resource")

			Eventually(func() bool {
				err, cnt := infwutils.RunPingTest(nodes.Items)
				if err != nil && cnt == len(nodes.Items) {
					return true
				}
				return false
			}, infwutils.Timeout, infwutils.Interval).Should(BeTrue())

			var stdOut, stdError string
			var metrics testutil.Metrics
			err = wait.PollImmediate(1*time.Second, 60*time.Second, func() (done bool, err error) {
				stdOut, stdError, err = pods.ExecCommand(testclient.Client, daemonPod, "/usr/bin/curl", "127.0.0.1:39301/metrics")

				if err != nil {
					return false, err
				}

				if stdError != "" {
					return false, fmt.Errorf("%s", stdError)
				}

				if stdOut == "" {
					return false, nil
				}
				metrics = testutil.NewMetrics()
				if err = testutil.ParseMetrics(stdOut, &metrics); err != nil {
					return false, fmt.Errorf("failed to parse metrics: %v", err)
				}

				sample, ok := metrics[infmetrics.MetricINFNamespace+"_"+infmetrics.MetricINFSubsystemNode+"_"+"packet_deny_total"]
				if !ok {
					return false, nil
				}
				if len(sample) == 0 {
					return false, nil
				}

				if sample[0].Value == 1 {
					return true, nil
				}

				return false, nil
			})

			Expect(err).To(BeNil())
			for _, metric := range infmetrics.GetPrometheusStatisticNames() {
				sample, ok := metrics[metric]
				Expect(ok).To(BeTrue())
				Expect(sample.Len() > 0).To(BeTrue())
			}
		})
	})
})
