package models

import (
	"context"
	"fmt"
	"log"

	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
)

func (nodeConfig *NodeConfig) Up(ctx context.Context, delete bool) error {
	if nodeConfig.Resources != nil {
		log.Println("Setting up dataplane ...")
		if err := nodeConfig.Resources.Reconcile(ctx, delete); err != nil {
			return fmt.Errorf("failed to reconcile dataplane: %w", err)
		}
	}
	return nil
}

func appendNoNil(targets []pkgreconcile.ResourceProvisionersList, target pkgreconcile.ResourceProvisionersList) []pkgreconcile.ResourceProvisionersList {
	if target == nil {
		return targets
	}
	return append(targets, target)
}

func (dpConfig *ResourcesConfig) DetectChanges(ctx context.Context, delete bool) (*pkgreconcile.ResourceListChangeSet, error) {

	var changeSet *pkgreconcile.ResourceListChangeSet

	reconcileTargets := make([]pkgreconcile.ResourceProvisionersList, 0)
	reconcileTargets = appendNoNil(reconcileTargets, dpConfig.VRF)
	reconcileTargets = appendNoNil(reconcileTargets, dpConfig.WireGuard)
	reconcileTargets = appendNoNil(reconcileTargets, dpConfig.VXLAN)
	reconcileTargets = appendNoNil(reconcileTargets, dpConfig.VethPair)
	reconcileTargets = appendNoNil(reconcileTargets, dpConfig.Bridge)
	reconcileTargets = appendNoNil(reconcileTargets, dpConfig.Dummy)
	reconcileTargets = appendNoNil(reconcileTargets, dpConfig.Route)

	for _, reconcileTarget := range reconcileTargets {
		log.Println("Detecting changes for", reconcileTarget.GetType(), "...")
		// subChangeSet, err := pkgreconcile.DetectChangesForProvisionersList(ctx, reconcileTarget)
		subChangeSet, err := reconcileTarget.DetectChanges(ctx, delete)
		if err != nil {
			return nil, fmt.Errorf("failed to detect changes for %s: %w", reconcileTarget.GetType(), err)
		}
		if subChangeSet != nil && subChangeSet.HasChanges() {
			log.Println("Found changes for", reconcileTarget.GetType())
			changeSet = changeSet.Merge(subChangeSet)
		}
	}

	return changeSet, nil
}

func (dpConfig *ResourcesConfig) Reconcile(ctx context.Context, delete bool) error {
	log.Println("Detecting changes for dataplane config ...")
	changeSet, err := dpConfig.DetectChanges(ctx, delete)
	if err != nil {
		return fmt.Errorf("failed to detect changes: %w", err)
	}

	maxLoop := 10
	iterId := 0

	for changeSet != nil && changeSet.HasChanges() && maxLoop > 0 {
		// log.Printf("Iteration %d: Found changeset, applying changes for dataplane config ...", iterId)
		// changeSet.Log()

		log.Println("Applying changes for dataplane config ...")
		if err := changeSet.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply changes: %w", err)
		}

		log.Println("Changeset is applied to dataplane config, detecting changes again ...")
		changeSet, err = dpConfig.DetectChanges(ctx, delete)
		if err != nil {
			return fmt.Errorf("failed to detect changes: %w", err)
		}
		maxLoop--
		iterId++
	}

	if maxLoop == 0 && changeSet != nil && changeSet.HasChanges() {
		return fmt.Errorf("failed to reconcile dataplane config, max loop reached")
	}

	return nil
}
