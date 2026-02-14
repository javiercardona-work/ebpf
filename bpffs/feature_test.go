package bpffs

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveBPFFSDelegation(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFFSDelegation)
}
