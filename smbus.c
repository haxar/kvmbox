// Copyright (c) 2011 Scott Mansell <phiren@gmail.com>
// Licensed under the MIT license
// Refer to the included LICENCE file.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

uint16_t eepromRead(uint8_t addr) {
    debugf("Eeprom read 0x%02x\n", addr);
    return 0;
}

uint16_t picRead(uint8_t cmd) {
    uint16_t ret = 0;

    switch (cmd) {
    case 0x4: // av pack
        ret = 0x07; // disconnected
        break;
    // Challenge. These are meant to be random, but the what the bios doesn't know can't hurt it.
    case 0x1c:
        ret = 0xde;
        break;
    case 0x1d:
        ret = 0xad;
        break;
    case 0x1e:
        ret = 0xbe;
        break;
    case 0x1f:
        ret = 0xef;
        break;
    default:
        debugf("PIC: unimplemented read: 0x%02x\n", cmd);
        break;
    }

    return ret;
}

void picWrite(uint8_t cmd, uint16_t data) {
    switch (cmd) {
    case 0x20:
        break;
    case 0x21:
        debugf("PIC: Loader is authenticated, we won't reset the cpu ;D\n");
        break;
    default:
        debugf("PIC: unimplemented write: 0x%02x\n", cmd);
        break;
    }
}

unsigned char address;
unsigned char command;
unsigned short data;

void smbusIO(uint16_t port, uint8_t direction, uint8_t size, uint8_t *p) {
    //printf("smbus: ");
    switch (direction) {
    case 1: // out
        switch (port) {
        case 0xc004:
            address = *p;
            break;
        case 0xc006:
            if (size == 1) data = *p;
            else data = *(uint16_t *)p;
            break;
        case 0xc008:
            command = *p;
            break;
        case 0xc000:
            break;//we don't care if the software writes to the status port
        case 0xc002:
            switch (address) {
            case 0x54 << 1 | 1:
                data = eepromRead(command);
                break;
            case 0x10 << 1 | 1:
                data = picRead(command);
                break;
            case 0x10 << 1 | 0:
                picWrite(command, data);
                break;
            default:
                if ((address & 1) == 0) { // Write
                    if (*p == 0xa) {
                        debugf("SMBus: Write %02x:%02x = 0x%02x\n", address>>1, command, data);
                    } else if (*p == 0xb) {
                        debugf("SMBus: Write %02x:%02x = 0x%04x\n", address>>1, command, data);
                    } else printf("SMBus: Unsupport opperation");
                } else {
                    debugf("SMBus: Read %02x:%02x\n", address>>1, command);
                }
            }
            break;
        default:
            debugf("smbus: unhandled out port 0x%04x\n", port);
            break;
        }
        break;
    case 0: // in
        switch (port) {
        case 0xc000:
            *p = 0x10; // Cycle complete
            break;
        case 0xc006:
            if (size == 1) *p = (uint8_t)data;
            else *(uint16_t *)p = data;
            break;
        default:
            debugf("smbus: unhandled port in 0x%04x\n", port);
            break;
        }
        break;
    }
}

