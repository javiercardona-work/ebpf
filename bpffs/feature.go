package bpffs

import (
	"errors"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

var haveBPFFSDelegation = internal.NewFeatureTest("BPFFS Privilege Delegation",
	func() error {
		tokenAttr := sys.TokenCreateAttr{
			BpffsFd: ^uint32(0),
			Flags:   0,
		}

		_, err := sys.TokenCreate(&tokenAttr)
		if errors.Is(err, unix.EINVAL) {
			return internal.ErrNotSupported
		} else if errors.Is(err, unix.EBADF) {
			return nil
		}
		return err
	},
	"6.9",
)
