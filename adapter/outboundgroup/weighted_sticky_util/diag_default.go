//go:build !beta_diag

package weightedsticky

// newProcessDiag selects the process-wide diagnostic writer. A normal build
// keeps the no-op emitter: it creates no file and records no observation.
func newProcessDiag() diagEmitter {
	return noopDiag{}
}
