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

#define TIMEOUT 1000

static struct libusb_device_handle *handle = NULL;

static int open_sansa_connect()
{
    handle = libusb_open_device_with_vid_pid(NULL, 0x0781, 0x7481);
    return handle ? 0 : -EIO;
}

static int write_data(int endpoint, unsigned char *buf, int len)
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

int main(int argc, char **argv)
{
    int result;
    unsigned char buf[4096];

    if (argc < 2)
    {
        printf("Usage: ./connecttool file1.srr file2.srr\n");
        return 1;
    }

    result = libusb_init(NULL);
    if (result < 0)
    {
        fprintf(stderr, "Failed to initialise libusb\n");
        return 1;
    }

    if (open_sansa_connect() != 0)
    {
        fprintf(stderr, "Unable to open Sansa Connect\n");
        libusb_exit(NULL);
        return 1;
    }

    result = libusb_claim_interface(handle, 0);
    if (result == 0)
        printf("claim resulted with %d\n", result);
    int file_nr;

    /* TODO: do commandline arguments parsing */
    int files = argc -1;
    char **filenames = &argv[1];

    for (file_nr = 0; file_nr < files; file_nr++)
    {
        FILE *f = fopen(filenames[file_nr], "r");
        if (f == NULL)
        {
            fprintf(stderr, "Unable to open file %s\n", filenames[file_nr]);
            return 1;
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

            if (write_data(1, buf, len) != 0)
            {
                fclose(f);
                libusb_close(handle);
                libusb_exit(NULL);
                return 1;
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

    return 0;
}
