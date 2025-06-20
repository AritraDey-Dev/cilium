// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

const (
	testCallerID1 = "test1"
	testCallerID2 = "test2"
)

type DiffStoreFixture struct {
	diffStore DiffStore[*slimv1.Service]
	signaler  *signaler.BGPCPSignaler
	slimCs    *slim_fake.Clientset
	hive      *hive.Hive
	watching  chan struct{} // closed once we have ensured there is a service watcher registered
}

func newDiffStoreFixture() *DiffStoreFixture {
	fixture := &DiffStoreFixture{
		watching: make(chan struct{}),
	}

	// Create a new faked CRD client set with the pools as initial objects
	fixture.slimCs = slim_fake.NewSimpleClientset()

	var once sync.Once
	fixture.slimCs.PrependWatchReactor("*", func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
		w := action.(k8sTesting.WatchAction)
		gvr := w.GetResource()
		ns := w.GetNamespace()
		watch, err := fixture.slimCs.Tracker().Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}
		once.Do(func() { close(fixture.watching) })
		return true, watch, nil
	})

	// Construct a new Hive with faked out dependency cells.
	fixture.hive = hive.New(
		cell.Provide(func(lc cell.Lifecycle, c k8sClient.Clientset) resource.Resource[*slimv1.Service] {
			return resource.New[*slimv1.Service](
				lc, utils.ListerWatcherFromTyped[*slimv1.ServiceList](
					c.Slim().CoreV1().Services(""),
				),
			)
		}),

		// Provide the faked client cells directly
		cell.Provide(func() k8sClient.Clientset {
			return &k8sFakeClient.FakeClientset{
				SlimFakeClientset: fixture.slimCs,
			}
		}),

		cell.Module(
			"bgpv1-test",
			"Testing module for bgpv1",
			cell.Provide(signaler.NewBGPCPSignaler),

			cell.Invoke(func(
				signaler *signaler.BGPCPSignaler,
				diffFactory DiffStore[*slimv1.Service],
			) {
				fixture.signaler = signaler
				fixture.diffStore = diffFactory
			}),

			cell.Provide(NewDiffStore[*slimv1.Service]),
		),
	)

	return fixture
}

// Test that adding and deleting objects trigger signals
func TestDiffSignal(t *testing.T) {
	fixture := newDiffStoreFixture()
	tracker := fixture.slimCs.Tracker()

	tlog := hivetest.Logger(t)
	err := fixture.hive.Start(tlog, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	<-fixture.watching

	fixture.diffStore.InitDiff(testCallerID1)
	fixture.diffStore.InitDiff(testCallerID2)

	// wait for initial sync signal
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	// Add an initial object.
	err = tracker.Add(&slimv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name: "service-a",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	// 1 upsert for the caller 1
	upserted, deleted, err := fixture.diffStore.Diff(testCallerID1)
	if err != nil {
		t.Fatal(err)
	}
	if len(upserted) != 1 {
		t.Fatal("Initial upserted not one")
	}
	if len(deleted) != 0 {
		t.Fatal("Initial deleted not zero")
	}

	// Add an object after init

	err = tracker.Add(&slimv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name: "service-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	// 1 upsert for the caller 1
	upserted, deleted, err = fixture.diffStore.Diff(testCallerID1)
	if err != nil {
		t.Fatal(err)
	}
	if len(upserted) != 1 {
		t.Fatal("Runtime upserted not one")
	}
	if len(deleted) != 0 {
		t.Fatal("Runtime deleted not zero")
	}

	// 2 upserts for the caller 2
	upserted, deleted, err = fixture.diffStore.Diff(testCallerID2)
	if err != nil {
		t.Fatal(err)
	}
	if len(upserted) != 2 {
		t.Fatal("Runtime upserted not two")
	}
	if len(deleted) != 0 {
		t.Fatal("Runtime deleted not zero")
	}

	// Delete an object after init

	err = tracker.Delete(slimv1.SchemeGroupVersion.WithResource("services"), "", "service-b")
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	// 1 deleted for the caller 1
	upserted, deleted, err = fixture.diffStore.Diff(testCallerID1)
	if err != nil {
		t.Fatal(err)
	}
	if len(upserted) != 0 {
		t.Fatal("Runtime upserted not zero")
	}
	if len(deleted) != 1 {
		t.Fatal("Runtime deleted not one")
	}

	// 1 deleted for the caller 2
	upserted, deleted, err = fixture.diffStore.Diff(testCallerID2)
	if err != nil {
		t.Fatal(err)
	}
	if len(upserted) != 0 {
		t.Fatal("Runtime upserted not zero")
	}
	if len(deleted) != 1 {
		t.Fatal("Runtime deleted not one")
	}

	err = fixture.hive.Stop(tlog, context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// Test that multiple events are correctly combined.
func TestDiffUpsertCoalesce(t *testing.T) {
	fixture := newDiffStoreFixture()
	tracker := fixture.slimCs.Tracker()

	tlog := hivetest.Logger(t)
	err := fixture.hive.Start(tlog, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	<-fixture.watching

	fixture.diffStore.InitDiff(testCallerID1)

	// Add first object
	err = tracker.Add(&slimv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name: "service-a",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add second object
	err = tracker.Add(&slimv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name: "service-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err := fixture.diffStore.Diff(testCallerID1)
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 2 {
		t.Fatal("Expected 2 upserted objects")
	}

	if len(deleted) != 0 {
		t.Fatal("Expected 0 deleted objects")
	}

	// Update first object
	err = tracker.Update(
		slimv1.SchemeGroupVersion.WithResource("services"),
		&slimv1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name: "service-a",
			},
			Spec: slimv1.ServiceSpec{
				ClusterIP: "1.2.3.4",
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	err = tracker.Delete(slimv1.SchemeGroupVersion.WithResource("services"), "", "service-b")
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = fixture.diffStore.Diff(testCallerID1)
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Expected 1 upserted object")
	}

	if len(deleted) != 1 {
		t.Fatal("Expected 1 deleted object")
	}

	// Update first object once
	err = tracker.Update(
		slimv1.SchemeGroupVersion.WithResource("services"),
		&slimv1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name: "service-a",
			},
			Spec: slimv1.ServiceSpec{
				ClusterIP: "2.3.4.5",
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Update first object twice
	err = tracker.Update(
		slimv1.SchemeGroupVersion.WithResource("services"),
		&slimv1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name: "service-a",
			},
			Spec: slimv1.ServiceSpec{
				ClusterIP: "3.4.5.6",
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = fixture.diffStore.Diff(testCallerID1)
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Expected 1 upserted object")
	}

	if len(deleted) != 0 {
		t.Fatal("Expected 1 deleted object")
	}

	if upserted[0].Spec.ClusterIP != "3.4.5.6" {
		t.Fatal("Expected to only see the latest update")
	}

	err = fixture.hive.Stop(tlog, context.Background())
	if err != nil {
		t.Fatal(err)
	}
}
