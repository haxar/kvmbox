// Copyright (c) 2011 Scott Mansell <phiren@gmail.com>
// Licensed under the MIT license
// Refer to the included LICENCE file.

#ifndef KVMBOX_H
#define KVMBOX_H

#include <sys/ioctl.h>
#include <linux/kvm.h>

#ifdef __cplusplus
extern "C" {
#endif

struct kvm {
	int fd;
	int vm_fd;
	int vcpu_fd;
	struct kvm_run *run;
	void *ram;
	void *rom;
};

#ifdef __cplusplus
}
#endif
#endif

