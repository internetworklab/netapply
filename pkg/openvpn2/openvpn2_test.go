package openvpn2_test

import (
	"testing"
)

func TestOpenVPN2ContainerCreateAndRemoval(t *testing.T) {
	// todo: rewrite such test
	// Strategy:
	// 1. Create the container
	// 2. Extract the container id and state
	// 3. Check that the state is "running"
	// 4. Stop the container
	// 5. If the container still exists, remote the container
	// 6. Confirm that the container is really removed
}
