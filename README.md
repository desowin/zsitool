# Sansa Connect Recovery tool

![Ubuntu Build Status](https://github.com/desowin/zsitool/actions/workflows/ubuntu.yml/badge.svg)

## Command line options

 * -e, --exploit rockbox_bootloader.bin
 * -c, --check filename.srr
 * -l, --linux zap.tar.gz zap.sig
 * -b, --bootloader vmlinux.srr initrd.srr
 * -s, --srrgen rockbox_bootloader.elf bootloader.srr

## Unsigned code execution notes

The -e option will flash and execute provided binary file.
The data will be flashed to 0x00120010 and copied to RAM at 0x01000000.
The execution will start at 0x01000000.

It is up to the code to erase the "recoverzap" parameter.
If "recoverzap" is not erased, Sansa Connect will show Recovery needed screen.
The workaround to this is to start console and wait for timeout (30 second).
Console will start if either UP or DOWN wheel button is pressed during power on.
