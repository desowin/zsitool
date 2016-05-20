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
    unsigned char buf[4096];

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
            {"bootloader", required_argument, 0, 'b'},
            {"linux",      required_argument, 0, 'l'},
            {"check",      required_argument, 0, 'c'},
            {"srrgen",     required_argument, 0, 's'},
            {0, 0, 0, 0}
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "b:l:c:s:",
                        long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c)
        {
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
            default:
                break;
        }
    }

    return retval;
}
