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
#include "signature.h"

#define TIMEOUT 1000

static int write_data(struct libusb_device_handle *handle, int endpoint, unsigned char *buf, int len)
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
                fprintf(stderr, "Error writing, error code %d\n", val);
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

            if (write_data(handle, 1, buf, len) != 0)
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

static bool check_file(const char *filename)
{
    uint8_t *buf;
    int buf_len;

    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return 1;
    }
    printf("Opening %s\n", filename);

    fseek(f, 0L, SEEK_END);
    buf_len = ftell(f);
    fseek(f, 0L, SEEK_SET);

    buf = (uint8_t*)malloc(buf_len);
    if (buf == NULL)
    {
        printf("Failed to allocate memory for file contents!\n");
        return 2;
    }

    /* Read file */
    fread(buf, sizeof(char), buf_len, f);

    print_srr_file_info(buf, buf_len);

    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2)
    {
        if (!check_file(argv[1]))
        {
            return 1;
        }
        return 0;
    }

    if (argc < 2)
    {
        printf("Usage: ./zsitool file1.srr file2.srr\n");
        return 1;
    }

    int files = argc - 1;
    char **filenames = &argv[1];
    if (!bootloader_transfer_files(filenames, files))
    {
        return 1;
    }
    return 0;
}
