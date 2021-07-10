# Sansa Connect Recovery tool

![Ubuntu Build Status](https://github.com/desowin/zsitool/actions/workflows/ubuntu.yml/badge.svg)
![Windows Build Status](https://github.com/desowin/zsitool/actions/workflows/windows.yml/badge.svg)

## Command line options

 * -e, --exploit rockbox_bootloader.bin
 * -a, --alternative-exploit payload.bin
 * -c, --check filename.srr
 * -l, --linux zap.tar.gz zap.sig
 * -b, --bootloader vmlinux.srr initrd.srr
 * -s, --srrgen rockbox_bootloader.elf bootloader.srr
 * -f, --forge bootloader.srr

## Unsigned code execution notes

The -e option will flash and execute provided binary file.
The data will be flashed to 0x00120010 and copied to RAM at 0x01000000.
The execution will start at 0x01000000.

The -a option will flash and execute provided binary file.
The -a option results in negligibly faster boot time than -e.
The data will be flashed to 0x00424010 and copied to RAM at 0x01544000.
The execution will start at 0x00424010.

It is up to the code to erase the "recoverzap" parameter.
If "recoverzap" is not erased, Sansa Connect will show Recovery needed screen.
The workaround to this is to start console and wait for timeout (30 second).
Console will start if either UP or DOWN wheel button is pressed during power on.

## Signature forgery

The signature forgery option is doomed to failure despite the fact that the signature
verification implementation in Sansa Connect bootloader is cryptographically broken.
Running forge option will simply waste a lot of CPU cycles.
