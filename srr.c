/*
 *  Copyright (c) 2016 Tomasz Moń <desowin@gmail.com>
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>
#include "srr.h"
#include "signature.h"

/* SIGNATURE_TEMPLATE_APPENDED_LENGTH bytes from SIGNATURE_TEMPLATE_APPENDED_OFFSET
 * are concatendated with message (SRR header + binary) and then hashed.
 * 4 bytes at SIGNATURE_TEMPLATE_CREATION_TIME_OFFSET can be modified in signature
 * forgery attempts in order to get different SHA1 results.
 */
#define SIGNATURE_TEMPLATE_APPENDED_OFFSET      5
#define SIGNATURE_TEMPLATE_APPENDED_LENGTH      5
#define SIGNATURE_TEMPLATE_CREATION_TIME_OFFSET 6

static const uint8_t signature_template[] =
{
    0x89, /* RFC4880 packet type: signature, old format, two byte length follows */
    0x00, 0x00, /* Packet length, ignored by bootloader */
    0x03, /* Signature version 3 */
    0x05, /* Must be 5 according to RFC4880 */
    0x00, /* RFC4880 signature type: binary document */
    0x00, 0x00, 0x00, 0x00, /* 4-byte creation time, can be anything */
    0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD, /* Key ID of the signer, ignored by bootloader */
    0x01, /* Public Key algorithm: RSA (Encrypt or Sign) */
    0x02, /* Hash type: SHA1 */
    0x00, 0x00, /* Left 16 bits of signed hash message, ignored by bootloader */
    0x00, 0x00, /* MPI Length in bits (Big Endian) */
    /* Then follows Big Endian MPI Data (RSA Signature) */
};

static bool load_program_data(Elf *e, uint32_t srr_start_addr,
                              char *srr_buffer, int srr_buffer_size, int *loaded)
{
    int i;
    size_t n;
    GElf_Phdr phdr;
    char *raw;
    size_t raw_size;

    raw = elf_rawfile(e, &raw_size);
    if (!raw)
    {
        fprintf(stderr, "Unable to get elf raw file contents\n");
        return false;
    }

    if (elf_getphdrnum(e, &n) != 0)
    {
        fprintf(stderr, "elf_getphdrnum() failed: %s\n", elf_errmsg(-1));
        return false;
    }

    for (i = 0; i < n; i++)
    {
        if (gelf_getphdr(e, i, &phdr) != &phdr)
        {
            fprintf(stderr, "getphdr() failed: %s\n", elf_errmsg(-1));
            return false;
        }

        if (phdr.p_type == PT_LOAD)
        {
            printf("LOAD: 0x%08jx %10jd bytes [file offset 0x%08jx]  ", phdr.p_paddr, phdr.p_filesz, phdr.p_offset);
            if ((phdr.p_paddr >= (srr_start_addr + SRR_HEADER_SIZE) &&
                ((phdr.p_paddr + phdr.p_filesz) <= (srr_start_addr + srr_buffer_size - SRR_SIG_SIZE)) &&
                phdr.p_filesz > 0))
            {
                int srr_offset;
                int end_offset;

                printf("loading\n");
                if (phdr.p_filesz + phdr.p_offset > raw_size)
                {
                    fprintf(stderr, "Malformed program header!\n");
                    return false;
                }

                srr_offset = phdr.p_paddr - srr_start_addr;
                end_offset = srr_offset + phdr.p_filesz;
                memcpy(&srr_buffer[srr_offset], &raw[phdr.p_offset], phdr.p_filesz);

                if (end_offset > *loaded)
                {
                    *loaded = end_offset;
                }
            }
            else
            {
                printf("discarding\n");
            }
        }
    }
    return true;
}

static bool find_start_address(Elf *e, uint32_t *out_addr)
{
    GElf_Shdr shdr;
    Elf_Scn* scn = NULL;
    Elf_Data* symbols = NULL;
    int n = 0, i;

    while ((scn = elf_nextscn(e, scn)) != NULL)
    {
        if (!gelf_getshdr(scn, &shdr))
        {
            fprintf(stderr, "gelf_getshdr() failed: %s\n", elf_errmsg(-1));
            return false;
        }

        if (shdr.sh_type == SHT_SYMTAB)
        {
            symbols = elf_getdata(scn, NULL);
            if (!symbols)
            {
                fprintf(stderr, "elf_getdata() failed: %s\n", elf_errmsg(-1));
                return false;
            }
            break;
        }
    }

    if (!scn)
    {
        fprintf(stderr, "Cannot find symbol table\n");
        return false;
    }

    if (shdr.sh_entsize)
    {
        n = shdr.sh_size / shdr.sh_entsize;
    }

    for (i = 0; i < n; i++)
    {
        GElf_Sym symbol;
        char *sym_name;
        gelf_getsym(symbols, i, &symbol);
        sym_name = elf_strptr(e, shdr.sh_link, symbol.st_name);
        if (strcmp(sym_name, "_start") == 0)
        {
            *out_addr = (uint32_t)symbol.st_value;
            return true;
        }
    }
    return false;
}

uint32_t uint32_from_le(uint32_t le)
{
    union
    {
        uint8_t u8[4];
        uint32_t u32;
    }
    value;

    value.u32 = le;
    return (value.u8[0]) |
           (value.u8[1] << 8) |
           (value.u8[2] << 16) |
           (value.u8[3] << 24);
}

uint32_t uint32_to_le(uint32_t host)
{
    union
    {
        uint8_t u8[4];
        uint32_t u32;
    }
    value;

    value.u8[0] = host & 0x000000FF;
    value.u8[1] = (host & 0x0000FF00) >> 8;
    value.u8[2] = (host & 0x00FF0000) >> 16;
    value.u8[3] = (host & 0xFF000000) >> 24;
    return value.u32;
}

#define SRR_DEFAULT_LOAD_ADDRESS          0x02000000

void generate_srr(char *input_elf_filename, char *output_filename)
{
    /* Partition layout:
     *   SRR header - 16 bytes
     *   Binary     - depends on size in SRR header
     *   Signature  - last SRR_SIG_SIZE bytes
     */

    /* Partition start of KERNEL component. */
    const uint32_t partition_start_addr = 0x00120000;
    /* KERNEL partition size is 2 MiB. */
    const uint32_t partition_size       = 0x00200000;

    FILE *output = NULL;
    char *srr_file_buf = NULL;
    SRR_Header *header = NULL;
    int srr_file_used = 0;
    uint32_t entry_point;

    int fd = -1;
    Elf *e = NULL;

    srr_file_buf = (char *)malloc(partition_size);
    if (!srr_file_buf)
    {
        fprintf(stderr, "Failed to allocate buffer!\n");
        goto exit;
    }
    memset(srr_file_buf, 0, partition_size);

    header = (SRR_Header*)&srr_file_buf[0];
    header->le_magic        = uint32_to_le(SRR_HEADER_MAGIC);
    header->le_load_address = uint32_to_le(SRR_DEFAULT_LOAD_ADDRESS);
    header->le_entry_point  = uint32_to_le(0xFFFFFFFF);
    header->le_file_length  = uint32_to_le(0);

    srr_file_used = SRR_HEADER_SIZE;

    /* Handle elf file */
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
        goto exit;
    }

    if ((fd = open(input_elf_filename, O_RDONLY, 0)) < 0)
    {
        fprintf(stderr, "open \"%s\" failed\n", input_elf_filename);
        goto exit;
    }

    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
        goto exit;
    }

    if (elf_kind(e) != ELF_K_ELF)
    {
        fprintf(stderr, "%s is not elf object!\n", input_elf_filename);
        goto exit;
    }

    if (!load_program_data(e, partition_start_addr, srr_file_buf, partition_size, &srr_file_used))
    {
        fprintf(stderr, "Failed to load program data!\n");
        goto exit;
    }

    if (!find_start_address(e, &entry_point))
    {
        fprintf(stderr, "Failed to find _start symbol!\n");
        goto exit;
    }

    /* Add signature template */
    if (srr_file_used > (partition_size - SRR_SIG_SIZE))
    {
        fprintf(stderr, "Not enough space for signature!\n");
        goto exit;
    }
    srr_file_used += SRR_SIG_SIZE;
    memcpy(&srr_file_buf[srr_file_used - SRR_SIG_SIZE], signature_template, sizeof(signature_template));

    /* Update header */
    header->le_entry_point = uint32_to_le(entry_point);
    header->le_file_length = uint32_to_le(srr_file_used - SRR_HEADER_SIZE);

    if (!print_srr_file_info((const uint8_t *)srr_file_buf, srr_file_used))
    {
        fprintf(stderr, "SRR file creation failed!\n");
        goto exit;
    }

    /* Write SRR buffer to file */
    if ((output = fopen(output_filename, "r")) != NULL)
    {
        fprintf(stderr, "Output file already exists, zsitool won't overwrite it.\n");
        goto exit;
    }

    if (!(output = fopen(output_filename, "wb")))
    {
        fprintf(stderr, "Unable to create output file!\n");
        goto exit;
    }

    if (fwrite(srr_file_buf, srr_file_used, 1, output) != 1)
    {
        fprintf(stderr, "Write failed!\n");
        fclose(output);
        remove(output_filename);
        output = NULL;
    }

    printf("SRR file successfully saved\n");

exit:
    if (output)
    {
        fclose(output);
    }
    free(srr_file_buf);
    if (e)
    {
        elf_end(e);
    }
    if (!(fd < 0))
    {
        close(fd);
    }
}

bool print_srr_header(SRR_Header *header)
{
    uint32_t magic;
    uint32_t load_address;
    uint32_t entry_point;
    uint32_t file_length;

    magic = uint32_from_le(header->le_magic);
    if (magic != SRR_HEADER_MAGIC)
    {
        return false;
    }
    load_address = uint32_from_le(header->le_load_address);
    entry_point = uint32_from_le(header->le_entry_point);
    file_length = uint32_from_le(header->le_file_length);

    printf("Load Address: 0x%08X\nEntry Point: 0x%08X\nData Length: %"PRIu32"\n",
           load_address, entry_point, file_length);

    return true;
}
