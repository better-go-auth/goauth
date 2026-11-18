// Package userdelete is the one user-deletion sequence shared by core /delete-user, admin /remove-user and
// the anonymous plugin, so the hard/soft choice (config User.GoAuth.SoftDelete) behaves the same everywhere.
package userdelete

import (
	"context"

	"github.com/better-go-auth/goauth/src/plugins"
)

// Deps are the steps a caller provides.
type Deps struct {
	// Soft keeps the user row as a tombstone (config User.GoAuth.SoftDelete). The default (false) is
	// better-auth's hard delete with cascade.
	Soft bool
	// RevokeSessions signs the user out on every device (database and secondary storage).
	RevokeSessions func(ctx context.Context, userID string) error
	// RemoveRows deletes the user's accounts and the user row (soft: tombstones the user row).
	RemoveRows func(ctx context.Context, userID string, soft bool) error
	// Hooks receive UserDeleted so plugins drop their per-user rows (two-factor, passkeys, members, ...).
	Hooks plugins.HookRegistry
}

// Run deletes userID.
//
// Hard delete (default): sessions → plugin rows (UserDeleted hooks) → accounts + user row. The plugin
// rows go first because their foreign keys point at the user row, like better-auth's onDelete: "cascade".
// Soft delete: sessions → accounts + tombstone → UserDeleted hooks (the row stays, nothing blocks).
// The hooks are best effort in both modes, like better-auth's cleanup.
func Run(ctx context.Context, d Deps, userID string) error {
	// Step 1: sign the user out everywhere
	if d.RevokeSessions != nil {
		if err := d.RevokeSessions(ctx, userID); err != nil {
			return err
		}
	}
	// Step 2 (hard): plugin rows before the user row they reference
	if !d.Soft && d.Hooks != nil {
		_ = d.Hooks.TriggerUserDeleted(ctx, userID)
	}
	// Step 3: accounts and the user row
	if d.RemoveRows != nil {
		if err := d.RemoveRows(ctx, userID, d.Soft); err != nil {
			return err
		}
	}
	// Step 4 (soft): plugin rows once the tombstone is written
	if d.Soft && d.Hooks != nil {
		_ = d.Hooks.TriggerUserDeleted(ctx, userID)
	}
	return nil
}
