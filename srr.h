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

#ifndef SRR_H
#define SRR_H

#include <stdint.h>

typedef struct __attribute__((packed))
{
    /*! SRR_HEADER_MAGIC */
     uint32_t le_magic;
     /*! Load address in RAM. It cannot overwrite bootloader or stack. */
     uint32_t le_load_address;
     /*! Entry point */
     uint32_t le_entry_point;
     /*! File length excluding sizeof(SRR_Header) */
     uint32_t le_file_length;
}
SRR_Header;

#define SRR_HEADER_MAGIC                           0xEEFFBBAA
/* Signature is last 2048 bytes of srr_file_data */
#define SRR_SIG_SIZE                                     2048
#define SRR_HEADER_SIZE                                    16

void generate_srr(char *input_elf_filename, char *output_filename);
bool print_srr_header(SRR_Header *header);

#endif /* SRR_H */
