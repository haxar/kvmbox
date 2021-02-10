// Copyright (c) 2011 Scott Mansell <phiren@gmail.com>
// Licensed under the MIT license
// Refer to the included LICENCE file.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>

#include "kvmbox.h"

void debugf(char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

#include "pci.c"
#include "smbus.c"

/* callback definitions as shown in Listing 2 go here */

void load_file(void *mem, const char *filename)
{
    int fd;
    int nr;

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Cannot open %s", filename);
        perror("open");
        exit(1);
    }
    while ((nr = read(fd, mem, 4096)) != -1 && nr != 0)
        mem += nr;

    if (nr == -1) {
        perror("read");
        exit(1);
    }
    close(fd);
}

void printRegs(struct kvm *kvm) {
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    int r = ioctl(kvm->vcpu_fd, KVM_GET_REGS, &regs);
    int s = ioctl(kvm->vcpu_fd, KVM_GET_SREGS, &sregs);
    if (r == -1 || s == -1) {
        fprintf(stderr, "Get Regs failed");
        return;
    }
    debugf("rax: 0x%08llx\n", regs.rax);
    debugf("rbx: 0x%08llx\n", regs.rbx);
    debugf("rcx: 0x%08llx\n", regs.rcx);
    debugf("rdx: 0x%08llx\n", regs.rdx);
    debugf("rsi: 0x%08llx\n", regs.rsi);
    debugf("rdi: 0x%08llx\n", regs.rdi);
    debugf("rsp: 0x%08llx\n", regs.rsp);
    debugf("rbp: 0x%08llx\n", regs.rbp);
    debugf("rip: 0x%08llx\n", regs.rip);
    debugf("=====================\n");
    debugf("cr0: 0x%016llx\n", sregs.cr0);
    debugf("cr2: 0x%016llx\n", sregs.cr2);
    debugf("cr3: 0x%016llx\n", sregs.cr3);
    debugf("cr4: 0x%016llx\n", sregs.cr4);
    debugf("cr8: 0x%016llx\n", sregs.cr8);
    debugf("gdt: 0x%04x:0x%08llx\n", sregs.gdt.limit, sregs.gdt.base);
    debugf("cs: 0x%08llx ds: 0x%08llx es: 0x%08llx\nfs: 0x%08llx gs: 0x%08llx ss: 0x%08llx\n",
             sregs.cs.base, sregs.ds.base, sregs.es.base, sregs.fs.base, sregs.gs.base, sregs.ss.base);
}

void mmio_handler(struct kvm *kvm) {
    uint32_t addr = kvm->run->mmio.phys_addr;
    if (kvm->run->mmio.is_write) {
        debugf("Write %i to 0x%08x\n", kvm->run->mmio.len, addr);
        debugf("0x%08x\n", *(uint32_t *)kvm->run->mmio.data);
    } else {
        debugf("Read %i from 0x%08x\n", kvm->run->mmio.len, addr);
    }
}

void smbusIO(uint16_t, uint8_t, uint8_t, uint8_t *);
void pciConfigIO(uint16_t, uint8_t, uint8_t, uint8_t *);

void io_handler(struct kvm *kvm) {
    uint8_t *p = (uint8_t *)kvm->run + kvm->run->io.data_offset;
    assert(kvm->run->io.count == 1);
    uint16_t port = kvm->run->io.port;
    if (port >= 0xc000 && port <= 0xc008) {
        smbusIO(port, kvm->run->io.direction, kvm->run->io.size, p);
    } else if (port == 0xcf8 || port == 0xcfc) {
        pciConfigIO(port, kvm->run->io.direction, kvm->run->io.size, p);
    } else if (kvm->run->io.direction) {
        debugf("I/O port 0x%04x out ", kvm->run->io.port);
        switch (kvm->run->io.size) {
        case 1:
            debugf("0x%02hhx\n", *(uint8_t *)p);
            break;
        case 2:
            debugf("0x%04hx\n", *(uint16_t *)p);
            break;
        case 4:
            debugf("0x%08x\n", *(uint32_t *)p);
            break;
        }
    } else {
        debugf("I/O 0x%04x in ", kvm->run->io.port);
        //*p = 0x20;
        switch (kvm->run->io.size) {
        case 1:
            debugf("byte\n");
            break;
        case 2:
            debugf("short\n");
            break;
        case 4:
            debugf("int\n");
            break;
        }
    }
    //sleep(1);
}

int vm_init(struct kvm *kvm, const char *ramfile, const char *romfile) {
    struct kvm_userspace_memory_region mem;
    int ret = 1;

    do {
        if ((kvm->fd = open("/dev/kvm", O_RDWR)) < 0) {
            fprintf(stderr, "%s(): open('/dev/kvm'): %m", __func__);
            break;
        }
        assert(ioctl(kvm->fd, KVM_GET_API_VERSION, 0) == 12);
        if ((kvm->vm_fd = ioctl(kvm->fd, KVM_CREATE_VM, 0)) < 0) {
            fprintf(stderr, "%s(): KVM_CREATE_VM: %m\n", __func__);
            break;
        }
        /* Give Intel its TSS space, I think this address is unused. */
        if (ioctl(kvm->vm_fd, KVM_SET_TSS_ADDR, 0x0f000000) < 0) {
            fprintf(stderr, "%s(): KVM_SET_TSS_ADDR: error assigning TSS space: %m\n", __func__);
            break;
        }
        kvm->ram            = memalign(0x00400000, 0x08000000); /* 128MiB of 4MiB aligned memory */
        mem.memory_size     = 0x08000000;
        mem.guest_phys_addr = 0x00000000;
        mem.userspace_addr  = (uintptr_t)kvm->ram;
        mem.flags           = 0;
        mem.slot            = 0;
        if (ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &mem) < 0) {
            fprintf(stderr, "%s(): KVM_SET_USER_MEMORY_REGION: ram: %m\n", __func__);
            break;
        }
        load_file(kvm->ram + 0x000f0000, "loader");
        load_file(kvm->ram + 0x00000000, ramfile);
        kvm->rom            = memalign(0x00100000, 0x00100000); /* 1MiB of 1MiB aligned memory */
        mem.memory_size     = 0x00100000;
        mem.guest_phys_addr = 0xfff00000;
        mem.userspace_addr  = (uintptr_t)kvm->rom;
        mem.flags           = 0;
        mem.slot            = 1;
        if (ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &mem) < 0) {
            fprintf(stderr, "%s(): KVM_SET_USER_MEMORY_REGION: rom: %m\n", __func__);
            break;
        }
        load_file(kvm->rom, romfile);
    } while ((ret = 0));

    return ret;
}

void nopSignalHandler() {
    // We don't actually need to do anything here, but we need to interrupt
    // the execution of the guest.
}

int main(int argc, char *argv[]) {
    struct kvm kvm;
    int ret = 1;

    do {
        if (argc < 3) {
            fprintf(stderr, "usage: %s <ramfile (64/128MiB)> <romfile (1024kiB)>\n", argv[0]);
            break;
        }
        if (vm_init(&kvm, argv[1], argv[2])) break;
#if 1
        ((uint8_t *)kvm.ram)[0x6b7] = 0x90;
        ((uint8_t *)kvm.ram)[0x6b8] = 0x90;
        ((uint8_t *)kvm.ram)[0x6b9] = 0x90;
        ((uint8_t *)kvm.ram)[0x6ba] = 0x90;
        ((uint8_t *)kvm.ram)[0x6bb] = 0x90;
#endif
        if ((kvm.vcpu_fd = ioctl(kvm.vm_fd, KVM_CREATE_VCPU, 0)) < 0) {
            fprintf(stderr, "%s(): KVM_CREATE_VCPU: %m\n", __func__);
            break;
        }
        if ((ret = ioctl(kvm.fd, KVM_GET_VCPU_MMAP_SIZE, 0)) < 0) {
            fprintf(stderr, "%s(): KVM_GET_VCPU_MMAP_SIZE: %m\n", __func__);
            break;
        }
        if ((kvm.run = mmap(NULL, ret, PROT_READ | PROT_WRITE, MAP_SHARED, kvm.vcpu_fd, 0)) == MAP_FAILED) {
            fprintf(stderr, "%s(): mmap(NULL, 0x%.08x): failed to map vcpu area: %m\n", __func__, ret);
            break;
        }
#if 1
        printRegs(&kvm);
#endif
    } while ((ret = 0));

    if (ret) return ret;

    signal(SIGUSR1, nopSignalHandler); // Prevent termination on USER1 signals

    while (!ret) {
        ioctl(kvm.vcpu_fd, KVM_RUN, 0);
        switch (kvm.run->exit_reason) {
        case KVM_EXIT_IO:
            io_handler(&kvm);
            break;
        case KVM_EXIT_HLT:
            debugf("halted\n");
            printRegs(&kvm);
            ret = 1;
            break;
        case KVM_EXIT_MMIO:
            mmio_handler(&kvm);
            break;
        case KVM_EXIT_INTR:
            debugf("Interrupt\n");
            ret = 2;
            break;
        case KVM_EXIT_SHUTDOWN:
            printRegs(&kvm);
            debugf("Triple fault\n");
            ret = 1;
            break;
        case KVM_EXIT_FAIL_ENTRY:
            debugf("Failed to enter emulation: %llx\n", kvm.run->fail_entry.hardware_entry_failure_reason);
            ret = 1;
            break;
        default:
            debugf("unhandled exit reason: %i\n", kvm.run->exit_reason);
            printRegs(&kvm);
            ret = 1;
            break;
        }
        if (ret == 1) raise(SIGTRAP);
    }

    return ret;
}

