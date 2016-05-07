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
#define _BSD_SOURCE
#include <endian.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "signature.h"

#define N_ELEMENTS(array) (sizeof(array)/sizeof(array[0]))

/*! RSA public exponent in Big Endian. */
static uint8_t be_exponent[] = { 0x29 };
/*! RSA modulus in Big Endian. */
static uint8_t be_modulus[] =
{
0xb5, 0x3e, 0x28, 0x3a, 0xd7, 0xcd, 0xae, 0x18, 0x85, 0x3a, 0xc5, 0x0c, 0xbc, 0xa4, 0x88, 0xf0,
0x9d, 0x48, 0x0e, 0x4d, 0x33, 0x2e, 0xe5, 0x83, 0xac, 0xa8, 0x27, 0x79, 0x46, 0x86, 0xa5, 0xe5,
0x1b, 0xc7, 0x12, 0xec, 0xea, 0xe1, 0x25, 0x86, 0xfe, 0x0e, 0xf8, 0x49, 0xa3, 0xe0, 0x47, 0x9a,
0x72, 0x46, 0xed, 0x9b, 0x03, 0x0f, 0xc7, 0x19, 0xf5, 0x24, 0x5d, 0x14, 0xff, 0x08, 0xc3, 0x74,
0x95, 0x26, 0x9f, 0x83, 0x8e, 0xe1, 0x57, 0xb9, 0x0e, 0xd9, 0x37, 0x54, 0x8a, 0x54, 0x30, 0x0c,
0x95, 0x24, 0x30, 0x5e, 0xa6, 0x17, 0x68, 0x4f, 0xcf, 0xdb, 0x3b, 0xee, 0x62, 0xeb, 0xa6, 0xac,
0xb0, 0xe2, 0x42, 0x82, 0x75, 0xdd, 0x9e, 0x84, 0xc7, 0x24, 0x1f, 0x8c, 0x7a, 0xe8, 0xec, 0x8e,
0xb2, 0x09, 0x0f, 0x69, 0x65, 0xa4, 0x9e, 0x2b, 0x57, 0x34, 0xa4, 0xd6, 0x71, 0xfd, 0x9b, 0x0e,
0x5e, 0xaf, 0x27, 0xe7, 0x56, 0xce, 0x33, 0xde, 0xfb, 0x75, 0x44, 0x8f, 0x6e, 0xf7, 0x9e, 0xfb,
0xc3, 0x96, 0x68, 0x99, 0x5f, 0xa5, 0x1a, 0xc4, 0x8f, 0x12, 0x6d, 0xfe, 0x52, 0x99, 0x26, 0xd2,
0x00, 0xc8, 0x37, 0x68, 0x2d, 0xb0, 0x73, 0xe3, 0x7e, 0x8a, 0xeb, 0xce, 0xdb, 0x7b, 0xbf, 0xb9,
0xd9, 0xe4, 0x07, 0x92, 0x17, 0x07, 0x48, 0xf5, 0x9b, 0x33, 0xf8, 0x8e, 0xbf, 0x61, 0xa8, 0x22,
0x15, 0x4d, 0x07, 0xcd, 0x89, 0x92, 0x63, 0x19, 0x00, 0xd5, 0x8d, 0x0e, 0x92, 0xee, 0x22, 0xbc,
0x4f, 0x2b, 0x96, 0x10, 0x99, 0xf4, 0xa4, 0x72, 0xf3, 0xd8, 0x03, 0x18, 0x83, 0x04, 0x36, 0x5a,
0x14, 0x87, 0xd6, 0xc6, 0xbb, 0xc4, 0xfe, 0x9c, 0x4d, 0xee, 0x52, 0x2e, 0x6f, 0x0b, 0xe6, 0xda,
0xaa, 0x0c, 0xba, 0xd3, 0xf3, 0xae, 0x76, 0x7c, 0xae, 0xfd, 0x71, 0xed, 0xa9, 0x7d, 0x01, 0xe1
};

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
 * \param[out] RSA_m_pow_d_mod_n BIGNUM to store RSA encrypted message,
 *                               which is pow(m, d) mod n.
 *
 * \return true if Sansa Connect bootloader would accept such signature.
 *              However the firmware check might still fail, because
 *              this does not mean that the RSA signature is valid!
 * \return false if Sansa Connect bootloader would fail firmware without
 *              even performing RSA check.
 */
static bool parse_rfc4880_signature(const uint8_t *signature,
                                    const uint8_t **sig_type_ptr,
                                    E_RFC4880_Hash *hash_type,
                                    BIGNUM *RSA_m_pow_d_mod_n)
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

    if (RSA_m_pow_d_mod_n != BN_bin2bn(mpi_data, mpi_length, RSA_m_pow_d_mod_n))
    {
        printf("Failed to convert MPI to BIGNUM!\n");
        return false;
    }

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
    BIGNUM *RSA_encrypted = NULL;
    BIGNUM *RSAe = NULL;
    BIGNUM *RSAn = NULL;
    BIGNUM *RSA_decrypted = NULL;
    BN_CTX *bignum_ctx = NULL;
    char *tmp;

    bool result = false;
    const uint8_t *rfc4880_hashed_data = NULL;
    E_RFC4880_Hash hash_type;

    if (srr_file_length < SRR_SIG_SIZE + SRR_HEADER_SIZE)
    {
        if (verbose)
        {
            printf("File is too small to be .srr file\n");
        }
        goto exit;
    }

    RSA_encrypted = BN_new();
    if (NULL == RSA_encrypted)
    {
        printf("Failed to allocate BIGNUM!\n");
        goto exit;
    }
    if (!parse_rfc4880_signature(&srr_file_data[srr_file_length-SRR_SIG_SIZE],
                                 &rfc4880_hashed_data, &hash_type, RSA_encrypted))
    {
        if (verbose)
        {
            printf("Invalid signature packet!\n");
        }
        goto exit;
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
        goto exit;
    }

    /* Load modulus and exponents. */
    RSAe = BN_bin2bn(be_exponent, N_ELEMENTS(be_exponent), NULL);
    if (RSAe == NULL)
    {
        fprintf(stderr, "Failed to load exponent!\n");
        goto exit;
    }
    RSAn = BN_bin2bn(be_modulus, N_ELEMENTS(be_modulus), NULL);
    if (RSAn == NULL)
    {
        fprintf(stderr, "Failed to load modulus!\n");
        goto exit;
    }

    RSA_decrypted = BN_new();
    if (RSA_decrypted == NULL)
    {
        fprintf(stderr, "Failed to allocate BIGNUM for RSA result!\n");
        goto exit;
    }

    bignum_ctx = BN_CTX_new();
    if (bignum_ctx == NULL)
    {
        fprintf(stderr, "Failed to allocate BIGNUM context!\n");
        goto exit;
    }

    /* Perform RSA. */
    if (!BN_mod_exp(RSA_decrypted, RSA_encrypted, RSAe, RSAn, bignum_ctx))
    {
        fprintf(stderr, "RSA operation failed!\n");
        goto exit;
    }

    tmp = BN_bn2hex(RSA_decrypted);
    printf("Signature: %s\n", tmp);
    OPENSSL_free(tmp);

    /* TODO: determine how Sansa Connect bootloader verifies signature. */

    result = true;

exit:
    BN_free(RSA_encrypted);
    BN_free(RSAe);
    BN_free(RSAn);
    BN_free(RSA_decrypted);
    return result;
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
