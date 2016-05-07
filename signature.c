/*
 *  Copyright (c) 2016 Tomasz Moń <desowin@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 3 of the License.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations including
 *  the two.
 *
 *  You must obey the GNU General Public License in all respects for all
 *  of the code used other than OpenSSL. If you modify file(s) with this
 *  exception, you may extend this exception to your version of the
 *  file(s), but you are not obligated to do so. If you do not wish to do
 *  so, delete this exception statement from your version. If you delete
 *  this exception statement from all source files in the program, then
 *  also delete it here.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses>.
 */

#define _DEFAULT_SOURCE
#include <endian.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include "signature.h"

/* Signature is last 2048 bytes of srr_file_data */
#define SRR_SIG_SIZE                                     2048
#define SRR_HEADER_SIZE                                    16

#define RFC4880_SIGNATURE_PACKET_TYPE                       2
#define RFC4880_PACKET_LENGTH_TYPE_MASK                  0x03
#define RFC4880_SIGNATURE_TYPE_BINARY_DOCUMENT           0x00
#define RFC4880_PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN 0x01

typedef enum
{
    E_RFC4880_HASH_SHA1 = 2,
    E_RFC4880_HASH_SHA256 = 8,
}
E_RFC4880_Hash;

/**
 * \brief Parses signature in a similar fashion to Sansa Connect bootloader.
 *
 * \param[in] signature Pointer to signature block within SRR file.
 * \param[out] sig_type_ptr Place to store pointer to data that needs to be
 *                          concatenated with actual data before hashing.
 * \param[out] hash_type Place to store hash method used.
 *
 * \return true if Sansa Connect bootloader would accept such signature.
 *              However the firmware check might still fail, because
 *              this does not mean that the RSA signature is valid!
 * \return false if Sansa Connect bootloader would fail firmware without
 *              even performing RSA check.
 */
static bool parse_rfc4880_signature(const uint8_t *signature,
                                    const uint8_t **sig_type_ptr,
                                    E_RFC4880_Hash *hash_type)
{
    uint8_t PTag;
    const uint8_t *mpi_data;
    int mpi_length;
    int hdr_len;

    PTag = signature[0];
    if (!((PTag & 0x80) /* Bit 7 must be always set */ &&
          !(PTag & 0x40) /* Only old packet format is allowed */ &&
          ((PTag & 0x3C) == (RFC4880_SIGNATURE_PACKET_TYPE << 2))))
    {
        return false;
    }

    switch (PTag & RFC4880_PACKET_LENGTH_TYPE_MASK)
    {
        case 0:
            /* Header is 2 bytes long (PTag + 1 byte length) */
            hdr_len = 2;
            break;
        case 1:
            /* Header is 3 bytes long (PTag + 2 byte length) */
            hdr_len = 3;
            break;
        case 2:
            /* Header is 5 bytes long (PTag + 4 byte length) */
            hdr_len = 5;
            break;
        default:
            /* Header is 1 bytes long and packet is of indeterminate length.
             * Sansa Connect bootloader rejects such packets.
             */
            return false;
    }

    if (signature[hdr_len] != 3)
    {
        /* Sansa Connect bootloader supports only Signatures version 3 */
        return false;
    }

    if (signature[hdr_len + 1] != 5)
    {
        /* This number must be 5 according to RFC4880.
         * Sansa Connect bootloader fails if it is different than 5.
         */
        return false;
    }

    /* Return pointer to:
     *   One-octet signature type.
     *   Four-octet creation time.
     * This 5 bytes must be concatenated with the data to be signed.
     */
    *sig_type_ptr = &signature[hdr_len + 2];

    /* Sansa Connect bootloader supports only signatures of binary documents. */
    if (signature[hdr_len + 2] != RFC4880_SIGNATURE_TYPE_BINARY_DOCUMENT)
    {
        return false;
    }

    /* Bootloader ignores Eight-octet Key ID of signer. */

    /* Public Key Algorithm Must be RSA (Encrypt or Sign). */
    if (signature[hdr_len + 15] != RFC4880_PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN)
    {
        return false;
    }

    /* Bootloader supports only SHA1 and SHA256. */
    *hash_type = (E_RFC4880_Hash)signature[hdr_len + 16];
    if ((*hash_type != E_RFC4880_HASH_SHA1) && (*hash_type != E_RFC4880_HASH_SHA256))
    {
        return false;
    }

    /* Bootloader ignores Two-octet field holding left 16 bits of signed hash value. */

    /* MPI comprising the signature (RSA signature value m**d mod n).
     *
     * Note: Bootloader does not check MPI length.
     */
    mpi_length = ((signature[hdr_len + 20] | ((int)signature[hdr_len + 19] << 8)) + 7) / 8;
    mpi_data = &signature[hdr_len + 21];

    /* Fail if MPI extends beyound SRR signature allocated space.
     * Sansa Connect bootloader is perfectly fine with that.
     * However only 2048 bytes of signature can be transferred/programmed.
     */
    if (mpi_length + hdr_len + 21 > SRR_SIG_SIZE)
    {
        return false;
    }

    /* TODO: Read MPI into BIGNUM */
    (void)mpi_data;
    (void)mpi_length;
    return true;
}

/**
 * \brief Validates SRR signature.
 *
 * \param srr_file_data SRR file contents.
 * \param srr_file_length @a srr_file_data length in bytes.
 * \param verbose true if function should print srr file information.
 *
 * \return true if @a srr_file_data is valid.
 * \return false if @a srr_file_data is not valid.
 */
static bool validate_srr_signature(const uint8_t *srr_file_data, int srr_file_length,
                                   bool verbose)
{
    const uint8_t *rfc4880_hashed_data = NULL;
    E_RFC4880_Hash hash_type;
    if (srr_file_length < SRR_SIG_SIZE + SRR_HEADER_SIZE)
    {
        if (verbose)
        {
            printf("File is too small to be .srr file\n");
        }
        return false;
    }

    if (!parse_rfc4880_signature(&srr_file_data[srr_file_length-SRR_SIG_SIZE],
                                 &rfc4880_hashed_data, &hash_type))
    {
        if (verbose)
        {
            printf("Invalid signature packet!\n");
        }
        return false;
    }

    if (hash_type == E_RFC4880_HASH_SHA1)
    {
        unsigned char md[SHA_DIGEST_LENGTH];
        int i;
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, srr_file_data, srr_file_length - SRR_SIG_SIZE);
        SHA1_Update(&ctx, rfc4880_hashed_data, 5);
        SHA1_Final(md, &ctx);

        printf("SHA1 Hash: ");
        for (i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            printf("%02x", md[i]);
        }
        printf("\n");
    }
    else if (hash_type == E_RFC4880_HASH_SHA256)
    {
        unsigned char md[SHA256_DIGEST_LENGTH];
        int i;
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, srr_file_data, srr_file_length - SRR_SIG_SIZE);
        SHA256_Update(&ctx, rfc4880_hashed_data, 5);
        SHA256_Final(md, &ctx);

        printf("SHA256 Hash: ");
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            printf("%02x", md[i]);
        }
        printf("\n");
    }
    else
    {
        if (verbose)
        {
            printf("Unsupported Hash type!\n");
        }
        return false;
    }

    return true;
}

/**
 * \brief Prints SRR file info.
 *
 * \param srr_file_data SRR file contents.
 * \param srr_file_length @a srr_file_data length in bytes.
 *
 * \return true if @a srr_file_data is valid.
 * \return false if @a srr_file_data is not valid.
 */
bool print_srr_file_info(const uint8_t *srr_file_data, int srr_file_length)
{
    uint32_t magic;
    uint32_t load_address;
    uint32_t entry_point;
    uint32_t file_length;

    if (srr_file_length < SRR_HEADER_SIZE)
    {
        printf("SRR file too small!\n");
        return false;
    }

    magic = le32toh(*(uint32_t*)(&srr_file_data[0]));
    if (magic != 0xEEFFBBAA)
    {
        printf("Invalid SRR file magic!\n");
        return false;
    }
    load_address = le32toh(*(uint32_t*)(&srr_file_data[4]));
    entry_point = le32toh(*(uint32_t*)(&srr_file_data[8]));
    file_length = le32toh(*(uint32_t*)(&srr_file_data[12]));

    printf("Load Address: 0x%08X\nEntry Point: 0x%08X\nData Length: %"PRIu32"\n",
           load_address, entry_point, file_length);

    if (file_length + SRR_HEADER_SIZE != (uint32_t)srr_file_length)
    {
        printf("Length in SRR header does not match file size (%d)!\n",
               srr_file_length);
    }
    return validate_srr_signature(srr_file_data, srr_file_length, true);
}