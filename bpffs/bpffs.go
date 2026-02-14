package bpffs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

const (
	bpffsMountPath = "/sys/fs/bpf"
)

// isBpfFs returns true if path resides on a BPF filesystem.
func isBpfFs(path string) (bool, error) {
	fsType, err := linux.FSType(path)
	if err != nil {
		return false, err
	}
	if fsType != unix.BPF_FS_MAGIC {
		return false, nil
	}

	return true, nil
}

type BPFFS struct {
	path    string
	bpffsFd *sys.FD
	tokenFd *sys.FD
}

func NewBPFFS(path string) (*BPFFS, error) {
	if path == "" {
		return nil, fmt.Errorf("bpffs path cannot be empty")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", path)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	return &BPFFS{
		path: abs,
	}, nil
}

func NewBPFFSFromPath(path string) (*BPFFS, error) {
	if path == "" {
		path = bpffsMountPath
	}

	bf, err := NewBPFFS(path)
	if err != nil {
		return nil, err
	}

	if mounted, err := isBpfFs(bf.path); err != nil {
		return nil, err
	} else if !mounted {
		return nil, fmt.Errorf("path %q is not bpffs", bf.path)
	}

	dirfd, err := unix.Open(bf.path, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open directory: %w", err)
	}

	bpffsFd, err := sys.NewFD(dirfd)
	if err != nil {
		_ = unix.Close(dirfd)
		return nil, err
	}

	bf.bpffsFd = bpffsFd
	return bf, nil
}

func (bf *BPFFS) Close() error {
	var errs []error
	if bf.tokenFd != nil {
		if err := bf.tokenFd.Close(); err != nil {
			errs = append(errs, err)
		}
		bf.tokenFd = nil
	}
	if bf.bpffsFd != nil {
		if err := bf.bpffsFd.Close(); err != nil {
			errs = append(errs, err)
		}
		bf.bpffsFd = nil
	}

	return errors.Join(errs...)
}

func (bf *BPFFS) Token() (*sys.FD, error) {
	if bf.tokenFd != nil {
		return bf.tokenFd.Dup()
	}

	if bf.bpffsFd == nil {
		return nil, fmt.Errorf("bpffs is not mounted")
	}

	if err := haveBPFFSDelegation(); err != nil {
		return nil, err
	}

	tokenAttr := sys.TokenCreateAttr{
		BpffsFd: bf.bpffsFd.Uint(),
	}

	tokenFd, err := sys.TokenCreate(&tokenAttr)
	if err != nil {
		return nil, err
	}

	bf.tokenFd = tokenFd
	return bf.tokenFd.Dup()
}
