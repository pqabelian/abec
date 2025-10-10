package blockchain

import "fmt"

// DeploymentError identifies an error that indicates a deployment ID was
// specified that does not exist.
type DeploymentError uint32

// Error returns the assertion error as a human-readable string and satisfies
// the error interface.
func (e DeploymentError) Error() string {
	return fmt.Sprintf("deployment ID %d does not exist", uint32(e))
}

// AssertError identifies an error that indicates an internal code consistency
// issue and should be treated as a critical and unrecoverable error.
type AssertError string

// Error returns the assertion error as a human-readable string and satisfies
// the error interface.
func (e AssertError) Error() string {
	return "assertion failed: " + string(e)
}
