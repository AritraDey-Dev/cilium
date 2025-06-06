// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type ipamMetrics struct {
	ConflictingPools    metric.Gauge
	AvailableIPs        metric.DeletableVec[metric.Gauge]
	UsedIPs             metric.DeletableVec[metric.Gauge]
	MatchingServices    metric.Gauge
	UnsatisfiedServices metric.Gauge
	EventProcessingTime metric.Vec[metric.Observer]
}

func newMetrics() *ipamMetrics {
	return &ipamMetrics{
		ConflictingPools: metric.NewGauge(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_lbipam_conflicting_pools",
			Namespace:  metrics.Namespace,
			Subsystem:  "lbipam",
			Name:       "conflicting_pools",
			Help:       "The number of conflicting pools",
		}),
		AvailableIPs: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_lbipam_ips_available",
			Namespace:  metrics.Namespace,
			Subsystem:  "lbipam",
			Name:       "ips_available",
			Help:       "The number of IP addresses available in a given pool",
		}, []string{"pool"}),
		UsedIPs: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_lbipam_ips_used",
			Namespace:  metrics.Namespace,
			Subsystem:  "lbipam",
			Name:       "ips_used",
			Help:       "The number of IP addresses used in a given pool",
		}, []string{"pool"}),
		MatchingServices: metric.NewGauge(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_lbipam_services_matching",
			Namespace:  metrics.Namespace,
			Subsystem:  "lbipam",
			Name:       "services_matching",
			Help:       "The number of services matching pools",
		}),
		UnsatisfiedServices: metric.NewGauge(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_lbipam_services_unsatisfied",
			Namespace:  metrics.Namespace,
			Subsystem:  "lbipam",
			Name:       "services_unsatisfied",
			Help:       "The number of services which did not receive all requested IPs",
		}),
		EventProcessingTime: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "_lbipam_event_processing_time_seconds",
			Namespace:  metrics.Namespace,
			Subsystem:  "lbipam",
			Name:       "event_processing_time_seconds",
			Help:       "The time taken to process an event",
		}, []string{"event", "resource"}),
	}
}
