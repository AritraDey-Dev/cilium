// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	resourceTypeNetworkPolicy = "NetworkPolicy"
)

var (
	allowAllNamespacesRequirement = slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}
)

// GetPolicyLabelsv1 extracts the name of np. It uses the name  from the Cilium
// annotation if present. If the policy's annotations do not contain
// the Cilium annotation, the policy's name field is used instead.
func GetPolicyLabelsv1(logger *slog.Logger, np *slim_networkingv1.NetworkPolicy) labels.LabelArray {
	if np == nil {
		logger.Warn("unable to extract policy labels because provided NetworkPolicy is nil")
		return nil
	}

	policyName, _ := annotation.Get(np, annotation.PolicyName, annotation.PolicyNameAlias)
	policyUID := np.UID

	if policyName == "" {
		policyName = np.Name
	}

	// Here we are using ExtractNamespaceOrDefault instead of ExtractNamespace because we know
	// for sure that the Object is namespace scoped, so if no namespace is provided instead
	// of assuming that the Object is cluster scoped we return the default namespace.
	ns := k8sUtils.ExtractNamespaceOrDefault(&np.ObjectMeta)

	return k8sCiliumUtils.GetPolicyLabels(ns, policyName, policyUID, resourceTypeNetworkPolicy)
}

func isPodSelectorSelectingCluster(podSelector *slim_metav1.LabelSelector) bool {
	if podSelector == nil {
		return false
	}
	if podSelector.MatchLabels[k8sConst.PolicyLabelCluster] != "" {
		return true
	}
	for _, expr := range podSelector.MatchExpressions {
		if expr.Key == k8sConst.PolicyLabelCluster {
			return true
		}
	}

	return false
}

func parseNetworkPolicyPeer(clusterName, namespace string, peer *slim_networkingv1.NetworkPolicyPeer) *api.EndpointSelector {
	if peer == nil {
		return nil
	}

	var retSel *api.EndpointSelector
	// The PodSelector should only reflect to the configured cluster unless the selector
	// explicitly targets another cluster already.
	if clusterName != cmtypes.PolicyAnyCluster && !isPodSelectorSelectingCluster(peer.PodSelector) {
		if peer.PodSelector == nil {
			peer.PodSelector = &slim_metav1.LabelSelector{}
		}
		if peer.PodSelector.MatchLabels == nil {
			peer.PodSelector.MatchLabels = map[string]slim_metav1.MatchLabelsValue{}
		}
		peer.PodSelector.MatchLabels[k8sConst.PolicyLabelCluster] = clusterName
	}

	if peer.NamespaceSelector != nil {
		namespaceSelector := &slim_metav1.LabelSelector{
			MatchLabels: make(map[string]string, len(peer.NamespaceSelector.MatchLabels)),
		}
		// We use our own special label prefix for namespace metadata,
		// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
		for k, v := range peer.NamespaceSelector.MatchLabels {
			namespaceSelector.MatchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
		}

		// We use our own special label prefix for namespace metadata,
		// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
		for _, matchExp := range peer.NamespaceSelector.MatchExpressions {
			lsr := slim_metav1.LabelSelectorRequirement{
				Key:      policy.JoinPath(k8sConst.PodNamespaceMetaLabels, matchExp.Key),
				Operator: matchExp.Operator,
			}
			if matchExp.Values != nil {
				lsr.Values = make([]string, len(matchExp.Values))
				copy(lsr.Values, matchExp.Values)
			}
			namespaceSelector.MatchExpressions =
				append(namespaceSelector.MatchExpressions, lsr)
		}

		// Empty namespace selector selects all namespaces (i.e., a namespace
		// label exists).
		if len(namespaceSelector.MatchLabels) == 0 && len(namespaceSelector.MatchExpressions) == 0 {
			namespaceSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
		}

		selector := api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, namespaceSelector, peer.PodSelector)
		retSel = &selector
	} else if peer.PodSelector != nil {
		podSelector := parsePodSelector(peer.PodSelector, namespace)
		selector := api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, podSelector)
		retSel = &selector
	}

	return retSel
}

func hasV1PolicyType(pTypes []slim_networkingv1.PolicyType, typ slim_networkingv1.PolicyType) bool {
	return slices.Contains(pTypes, typ)
}

// ParseNetworkPolicy parses a k8s NetworkPolicy. Returns a list of
// Cilium policy rules that can be added, along with an error if there was an
// error sanitizing the rules.
func ParseNetworkPolicy(logger *slog.Logger, clusterName string, np *slim_networkingv1.NetworkPolicy) (api.Rules, error) {
	if np == nil {
		return nil, fmt.Errorf("cannot parse NetworkPolicy because it is nil")
	}

	ingresses := []api.IngressRule{}
	egresses := []api.EgressRule{}

	// Since we know that the object NetworkPolicy is namespace scoped we assign
	// namespace to default namespace if the field is empty in the object.
	namespace := k8sUtils.ExtractNamespaceOrDefault(&np.ObjectMeta)

	for _, iRule := range np.Spec.Ingress {
		fromRules := []api.IngressRule{}
		if len(iRule.From) > 0 {
			for _, rule := range iRule.From {
				ingress := api.IngressRule{}
				endpointSelector := parseNetworkPolicyPeer(clusterName, namespace, &rule)

				if endpointSelector != nil {
					ingress.FromEndpoints = append(ingress.FromEndpoints, *endpointSelector)
				} else {
					// No label-based selectors were in NetworkPolicyPeer.
					logger.Debug("NetworkPolicyPeer does not have PodSelector or NamespaceSelector", logfields.K8sNetworkPolicyName, np.Name)
				}

				// Parse CIDR-based parts of rule.
				if rule.IPBlock != nil {
					ingress.FromCIDRSet = append(ingress.FromCIDRSet, ipBlockToCIDRRule(rule.IPBlock))
				}

				fromRules = append(fromRules, ingress)
			}
		} else {
			// Based on NetworkPolicyIngressRule docs:
			//   From []NetworkPolicyPeer
			//   If this field is empty or missing, this rule matches all
			//   sources (traffic not restricted by source).
			ingress := api.IngressRule{}
			ingress.FromEndpoints = append(ingress.FromEndpoints, api.WildcardEndpointSelector)

			fromRules = append(fromRules, ingress)
		}

		// We apply the ports to all rules generated from the From section
		if len(iRule.Ports) > 0 {
			toPorts := parsePorts(iRule.Ports)
			for i := range fromRules {
				fromRules[i].ToPorts = toPorts
			}
		}

		ingresses = append(ingresses, fromRules...)
	}

	for _, eRule := range np.Spec.Egress {
		toRules := []api.EgressRule{}

		if len(eRule.To) > 0 {
			for _, rule := range eRule.To {
				egress := api.EgressRule{}
				if rule.NamespaceSelector != nil || rule.PodSelector != nil {
					endpointSelector := parseNetworkPolicyPeer(clusterName, namespace, &rule)

					if endpointSelector != nil {
						egress.ToEndpoints = append(egress.ToEndpoints, *endpointSelector)
					} else {
						logger.Debug("NetworkPolicyPeer does not have PodSelector or NamespaceSelector", logfields.K8sNetworkPolicyName, np.Name)
					}
				}
				if rule.IPBlock != nil {
					egress.ToCIDRSet = append(egress.ToCIDRSet, ipBlockToCIDRRule(rule.IPBlock))
				}

				toRules = append(toRules, egress)
			}
		} else {
			// Based on NetworkPolicyEgressRule docs:
			//   To []NetworkPolicyPeer
			//   If this field is empty or missing, this rule matches all
			//   destinations (traffic not restricted by destination)
			egress := api.EgressRule{}
			egress.ToEndpoints = append(egress.ToEndpoints, api.WildcardEndpointSelector)

			toRules = append(toRules, egress)
		}

		// We apply the ports to all rules generated from the To section
		if len(eRule.Ports) > 0 {
			toPorts := parsePorts(eRule.Ports)
			for i := range toRules {
				toRules[i].ToPorts = toPorts
			}
		}

		egresses = append(egresses, toRules...)
	}

	// Convert the k8s default-deny model to the Cilium default-deny model
	// spec:
	//  podSelector: {}
	//  policyTypes:
	//	  - Ingress
	// Since k8s 1.7 doesn't contain any PolicyTypes, we default deny
	// if podSelector is empty and the policyTypes is not egress
	if len(ingresses) == 0 &&
		(hasV1PolicyType(np.Spec.PolicyTypes, slim_networkingv1.PolicyTypeIngress) ||
			!hasV1PolicyType(np.Spec.PolicyTypes, slim_networkingv1.PolicyTypeEgress)) {
		ingresses = []api.IngressRule{{}}
	}

	// Convert the k8s default-deny model to the Cilium default-deny model
	// spec:
	//  podSelector: {}
	//  policyTypes:
	//	  - Egress
	if len(egresses) == 0 && hasV1PolicyType(np.Spec.PolicyTypes, slim_networkingv1.PolicyTypeEgress) {
		egresses = []api.EgressRule{{}}
	}

	podSelector := parsePodSelector(&np.Spec.PodSelector, namespace)

	// The next patch will pass the UID.
	rule := api.NewRule().
		WithEndpointSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, podSelector)).
		WithLabels(GetPolicyLabelsv1(logger, np)).
		WithIngressRules(ingresses).
		WithEgressRules(egresses)

	if err := rule.Sanitize(); err != nil {
		return nil, err
	}

	return api.Rules{rule}, nil
}

func parsePodSelector(podSelectorIn *slim_metav1.LabelSelector, namespace string) *slim_metav1.LabelSelector {
	podSelector := &slim_metav1.LabelSelector{
		MatchLabels: make(map[string]slim_metav1.MatchLabelsValue, len(podSelectorIn.MatchLabels)),
	}
	maps.Copy(podSelector.MatchLabels, podSelectorIn.MatchLabels)
	// The PodSelector should only reflect to the same namespace
	// the policy is being stored, thus we add the namespace to
	// the MatchLabels map.
	podSelector.MatchLabels[k8sConst.PodNamespaceLabel] = namespace

	for _, matchExp := range podSelectorIn.MatchExpressions {
		lsr := slim_metav1.LabelSelectorRequirement{
			Key:      matchExp.Key,
			Operator: matchExp.Operator,
		}
		if matchExp.Values != nil {
			lsr.Values = make([]string, len(matchExp.Values))
			copy(lsr.Values, matchExp.Values)
		}
		podSelector.MatchExpressions =
			append(podSelector.MatchExpressions, lsr)
	}
	return podSelector
}

func ipBlockToCIDRRule(block *slim_networkingv1.IPBlock) api.CIDRRule {
	cidrRule := api.CIDRRule{}
	cidrRule.Cidr = api.CIDR(block.CIDR)
	for _, v := range block.Except {
		cidrRule.ExceptCIDRs = append(cidrRule.ExceptCIDRs, api.CIDR(v))
	}
	return cidrRule
}

// parsePorts converts list of K8s NetworkPolicyPorts to Cilium PortRules.
func parsePorts(ports []slim_networkingv1.NetworkPolicyPort) []api.PortRule {
	portRules := []api.PortRule{}
	for _, port := range ports {
		protocol := api.ProtoTCP
		if port.Protocol != nil {
			protocol, _ = api.ParseL4Proto(string(*port.Protocol))
		}

		portStr := "0"
		var endPort int32
		if port.Port != nil {
			portStr = port.Port.String()
		}
		if port.EndPort != nil {
			endPort = *port.EndPort
		}

		portRule := api.PortRule{
			Ports: []api.PortProtocol{
				{Port: portStr, EndPort: endPort, Protocol: protocol},
			},
		}

		portRules = append(portRules, portRule)
	}

	return portRules
}
