package collector

import "fmt"

// diagnostics accumulates non-fatal collection problems: permission denials
// (which skip a surface) and feature-unavailable warnings.
type diagnostics struct {
	permissionErrors []string
	warnings         []string
}

// addPermissionError records a pre-formatted permission-error string.
func (d *diagnostics) addPermissionError(msg string) {
	d.permissionErrors = append(d.permissionErrors, msg)
}

// surfacePermissionDenied records that an audit/internal surface was skipped
// because the App (or PAT) lacks a permission. The surface's pointer field
// stays nil (omitempty keeps it out of the artifact) and this message lands in
// Diagnostics.PermissionErrors so the customer knows what to grant.
func (d *diagnostics) surfacePermissionDenied(surface, missingPerm string) {
	d.addPermissionError(fmt.Sprintf("surface %s skipped: permission denied (grant %s)", surface, missingPerm))
}

// surfaceUnavailable records that a surface requires an org feature the customer
// doesn't have (e.g. Enterprise Cloud for the audit log, or a fine-grained-token
// policy for PAT inventory). Informational, not an error: it lands in
// Diagnostics.Warnings and never fails the run.
func (d *diagnostics) surfaceUnavailable(surface, requirement string) {
	d.warnings = append(d.warnings, fmt.Sprintf("surface %s skipped: %s", surface, requirement))
}

// memberNamesIncomplete records that display names are missing from some
// member rows for a reason other than the user not setting one, so consumers
// don't read an absent name as "not set".
func (d *diagnostics) memberNamesIncomplete(reason string) {
	d.warnings = append(d.warnings, "members: display names incomplete: "+reason)
}

// build returns the output Diagnostics, or nil when there's nothing to report.
func (d *diagnostics) build() *Diagnostics {
	if len(d.permissionErrors) == 0 && len(d.warnings) == 0 {
		return nil
	}
	return &Diagnostics{PermissionErrors: d.permissionErrors, Warnings: d.warnings}
}
