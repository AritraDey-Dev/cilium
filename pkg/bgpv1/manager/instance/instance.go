// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package instance

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// ServerWithConfig is a container for providing interface with underlying router implementation
// and Cilium's BGP control plane related configuration.
//
// It exports a method set for manipulating the BgpServer. However, this
// struct is a dumb object. The calling code is required to keep the BgpServer's
// configuration and associated configuration fields in sync.
//
// This is used in BGPv1 implementation.
type ServerWithConfig struct {
	// ASN is the local ASN number of the virtual router instance.
	ASN uint32

	// backed BgpServer configured in accordance to the accompanying
	// CiliumBGPVirtualRouter configuration.
	Server types.Router

	// The CiliumBGPVirtualRouter configuration which drives the configuration
	// of the above BgpServer.
	//
	// If this field is nil it means the above BgpServer has had no
	// configuration applied to it.
	Config *v2alpha1.CiliumBGPVirtualRouter

	// ReconcilerMetadata holds reconciler-specific metadata keyed by the reconciler name,
	// opaque outside the respective reconciler.
	ReconcilerMetadata map[string]any
}

// NewServerWithConfig will start an underlying BgpServer utilizing types.ServerParameters
// for its initial configuration.
//
// The returned ServerWithConfig has a nil CiliumBGPVirtualRouter config, and is
// ready to be provided to ReconcileBGPConfig.
//
// Canceling the provided context will kill the BgpServer along with calling the
// underlying BgpServer's Stop() method.
func NewServerWithConfig(ctx context.Context, log *slog.Logger, params types.ServerParameters) (*ServerWithConfig, error) {
	s, err := gobgp.NewGoBGPServer(ctx, log, params)
	if err != nil {
		return nil, err
	}
	return &ServerWithConfig{
		ASN:                params.Global.ASN,
		Server:             s,
		Config:             nil,
		ReconcilerMetadata: make(map[string]any),
	}, nil
}

// BGPInstance is a container for providing interface with underlying router implementation.
//
// This is used in BGPv2 implementation.
type BGPInstance struct {
	Name                string
	Global              types.BGPGlobal
	CancelCtx           context.CancelFunc
	Config              *v2.CiliumBGPNodeInstance
	Router              types.Router
	stateNotificationCh chan struct{}
}

func (i *BGPInstance) NotifyStateChange() {
	select {
	case i.stateNotificationCh <- struct{}{}:
	default:
	}
}

// NewBGPInstance will start an underlying BGP instance utilizing types.ServerParameters
// for its initial configuration.
//
// The returned BGPInstance has a nil CiliumBGPNodeInstance config, and is
// ready to be provided to ReconcileBGPConfigV2.
//
// Canceling the provided context will kill the BGP instance along with calling the
// underlying Router's Stop() method.
func NewBGPInstance(ctx context.Context, log *slog.Logger, name string, params types.ServerParameters) (*BGPInstance, error) {
	gobgpCtx, cancel := context.WithCancel(ctx)
	s, err := gobgp.NewGoBGPServer(gobgpCtx, log, params)
	if err != nil {
		cancel()
		return nil, err
	}

	return &BGPInstance{
		Name:                name,
		Global:              params.Global,
		CancelCtx:           cancel,
		Config:              nil,
		Router:              s,
		stateNotificationCh: params.StateNotification,
	}, nil
}
