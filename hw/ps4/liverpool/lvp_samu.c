/*
 * QEMU model of Liverpool's Secure Asset Management Unit (SAMU) device.
 *
 * Copyright (c) 2017-2018 Alexandro Sanchez Bach
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "lvp_samu.h"
#include "lvp_gart.h"
#include "qapi/error.h"
#include "xxhash/xxhash.h"
#include "crypto/random.h"
#include "hw/ps4/macros.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"

#include <zlib.h>
#include <zip.h>

/* SAMU debugging */
#define DEBUG_SAMU 1

#define DPRINTF(...) \
do { \
    if (DEBUG_SAMU) { \
        fprintf(stderr, "lvp-gc (%s:%d): ", __FUNCTION__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
    } \
} while (0)

/* SAMU Secure Kernel emulation (based on 5.00) */
#include "sam/modules/sbl_pupmgr.h"
#include "sam/modules/sbl_authmgr.h"

#define MODULE_PUP_MGR    "80010006"
#define MODULE_AUTH_MGR   "80010008"
#define MODULE_IDATA_MGR  "80010009"
#define MODULE_KEY_MGR    "8001000B"

#define AUTHID_PUP_MGR    0x3E00000000000003ULL
#define AUTHID_AUTH_MGR   0x3E00000000000005ULL
#define AUTHID_IDATA_MGR  0x3E00000000000006ULL
#define AUTHID_KEY_MGR    0x3E00000000000007ULL

#define SAMU_VMID  15

static zip_t *blobs_zip = NULL;

/* Fake-crypto */
void liverpool_gc_samu_fakedecrypt(uint8_t *out_buffer,
    const uint8_t *in_buffer, uint64_t in_length)
{
    uint64_t hash;
    char filename[256];
    zip_stat_t stat;
    zip_file_t *file;
    size_t read;

    /* compute filename of decrypted blob */
    hash = XXH64(in_buffer, in_length, 0);
    if (!hash) {
        printf("qemu: samu-fakedecrypt: Could not hash input data\n");
        return;
    }
    snprintf(filename, sizeof(filename), "%llX.bin", hash);

    /* return decrypted blob contents */
    if (zip_stat(blobs_zip, filename, 0, &stat) == -1) {
        printf("qemu: samu-fakedecrypt: Could not find decrypted blob: %s\n", filename);
        qemu_hexdump(in_buffer, stdout, "", in_length > 0x80 ? 0x80 : in_length);
        return;
    }
    if (in_length != stat.size) {
        printf("qemu: samu-fakedecrypt: Decrypted blob size (%lld) is different from input (%lld) for: %s\n",
            in_length, stat.size, filename);
    }
    file = zip_fopen_index(blobs_zip, stat.index, 0);
    read = zip_fread(file, out_buffer, stat.size);
    if (read != stat.size) {
        printf("qemu: samu-fakedecrypt: Read %lld bytes instead of %lld for %s\n", read, in_length, filename);
    }
    zip_fclose(file);
}

/* memory */
void* samu_map(samu_state_t *s,
    hwaddr addr, hwaddr *plen, bool is_write)
{
    gart_state_t* gart = s->gart;
    return address_space_map(gart->as[SAMU_VMID], addr, plen, is_write);
}

void samu_unmap(samu_state_t *s,
    void *buffer, hwaddr len, bool is_write, hwaddr access_len)
{
    gart_state_t* gart = s->gart;
    address_space_unmap(gart->as[SAMU_VMID], buffer, len, is_write, access_len);
}

/* SAMU emulation */
static void samu_packet_io_write(samu_state_t *s,
    samu_packet_t *reply, int fd, void *buffer, size_t size)
{
    reply->command = SAMU_CMD_IO_WRITE;
    reply->status = 0;
    reply->data.io_write.fd = fd;
    reply->data.io_write.size = size;
    memcpy(&reply->data.io_write.data, buffer, size);
}

static uint32_t samu_packet_spawn(samu_state_t *s,
    const samu_packet_t *query, samu_packet_t *reply)
{
    const
    samu_command_service_spawn_t *query_spawn = &query->data.service_spawn;
    samu_command_service_spawn_t *reply_spawn = &reply->data.service_spawn;
    uint64_t module_id = 0; // TODO: The module ID is just an increasing number starting from 0, not an authentication ID

    if (!strncmp(query_spawn->name, MODULE_PUP_MGR, 8)) {
        module_id = AUTHID_PUP_MGR;
        sbl_pupmgr_spawn();
    }
    if (!strncmp(query_spawn->name, MODULE_AUTH_MGR, 8)) {
        module_id = AUTHID_AUTH_MGR;
    }
    if (!strncmp(query_spawn->name, MODULE_KEY_MGR, 8)) {
        module_id = AUTHID_KEY_MGR;
    }
    if (!module_id) {
        printf("%s: Unknown module: %s\n", __FUNCTION__, query_spawn->name);
    }
    reply_spawn->args[0] = (uint32_t)(module_id >> 32);
    reply_spawn->args[1] = (uint32_t)(module_id);
    return 0;
}

/* samu ccp */
static void samu_packet_ccp_aes(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    uint64_t data_size;
    uint64_t in_addr, out_addr;
    uint32_t in_slot, out_slot, key_slot, iv_slot;
    void    *in_data,*out_data,*key_data,*iv_data;
    hwaddr   in_size, out_size, key_size, iv_size;

    data_size = query_ccp->aes.data_size;
    in_size = data_size;
    out_size = data_size;

    in_addr = query_ccp->aes.in_addr;
    in_data = address_space_map(&address_space_memory, in_addr, &in_size, true);

    if (query_ccp->opcode & CCP_FLAG_SLOT_OUT) {
        out_slot = *(uint32_t*)&query_ccp->aes.out_addr;
        out_data = s->slots[out_slot];
    } else {
        out_addr = query_ccp->aes.out_addr;
        out_data = address_space_map(&address_space_memory, out_addr, &out_size, true);
    }

    if (query_ccp->opcode & CCP_FLAG_SLOT_KEY) {
        key_slot = *(uint32_t*)&query_ccp->aes.key;
        key_data = s->slots[key_slot];
    } else {
        key_data = query_ccp->aes.key;
    }

    // TODO/HACK: We don't have keys, so use hardcoded blobs instead
    liverpool_gc_samu_fakedecrypt(out_data, in_data, data_size);

    address_space_unmap(&address_space_memory, in_data, in_size, true, in_size);
    if (!(query_ccp->opcode & CCP_FLAG_SLOT_OUT)) {
        address_space_unmap(&address_space_memory, out_data, out_size, true, out_size);
    }
}

static void samu_packet_ccp_aes_insitu(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    DPRINTF("unimplemented");
}

static void samu_packet_ccp_xts(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    uint64_t data_size;
    uint64_t in_addr, out_addr;
    uint32_t in_slot, out_slot, key_slot;
    void    *in_data,*out_data,*key_data;
    hwaddr   in_size, out_size, key_size;

    data_size = query_ccp->xts.num_sectors * 512;
    in_size = data_size;
    out_size = data_size;

    in_addr = query_ccp->aes.in_addr;
    in_data = address_space_map(&address_space_memory, in_addr, &in_size, true);

    if (query_ccp->opcode & CCP_FLAG_SLOT_OUT) {
        out_slot = *(uint32_t*)&query_ccp->xts.out_addr;
        out_data = s->slots[out_slot];
    } else {
        out_addr = query_ccp->xts.out_addr;
        out_data = address_space_map(&address_space_memory, out_addr, &out_size, true);
    }

    if (query_ccp->opcode & CCP_FLAG_SLOT_KEY) {
        key_slot = *(uint32_t*)&query_ccp->xts.key;
        key_data = s->slots[key_slot];
    } else {
        key_data = query_ccp->xts.key;
    }

    memcpy(out_data, in_data, data_size);
}

static void samu_packet_ccp_sha(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    DPRINTF("unimplemented");
}

static void samu_packet_ccp_rsa(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    DPRINTF("unimplemented");
}

static void samu_packet_ccp_pass(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    DPRINTF("unimplemented");
}

static void samu_packet_ccp_ecc(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    DPRINTF("unimplemented");
}

static void samu_packet_ccp_zlib(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    int ret;
    uint8_t *in_data;
    uint8_t *out_data;
    hwaddr in_mapsize = query_ccp->zlib.in_size;
    hwaddr out_mapsize = query_ccp->zlib.out_size;
    z_stream stream;

    in_data = address_space_map(&address_space_memory,
        query_ccp->zlib.in_addr, &in_mapsize, false);
    out_data = address_space_map(&address_space_memory,
        query_ccp->zlib.out_addr, &out_mapsize, true);

    memset(&stream, 0, sizeof(stream));
    stream.next_in = in_data;
    stream.avail_in = query_ccp->zlib.in_size;
    stream.next_out = out_data;
    stream.avail_out = query_ccp->zlib.out_size;

    ret = inflateInit2(&stream, MAX_WBITS);
    if (ret != Z_OK) {
        DPRINTF("inflateInit2 failed (%d).\n", ret);
        goto error;
    }
    ret = inflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        DPRINTF("inflate failed (%d).\n", ret);
        inflateEnd(&stream);
        goto error;
    }
    ret = inflateEnd(&stream);
    if (ret != Z_OK) {
        DPRINTF("inflateEnd failed (%d).\n", ret);
        goto error;
    }

error:
    address_space_unmap(&address_space_memory, in_data,
        in_mapsize, false, in_mapsize);
    address_space_unmap(&address_space_memory, out_data,
        out_mapsize, true, out_mapsize);
}

static void samu_packet_ccp_trng(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    DPRINTF("unimplemented");
}

static void samu_packet_ccp_hmac(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    DPRINTF("unimplemented");
}

static void samu_packet_ccp_snvs(samu_state_t *s,
    const samu_command_service_ccp_t *query_ccp, samu_command_service_ccp_t *reply_ccp)
{
    DPRINTF("unimplemented");
}

static uint32_t samu_packet_ccp(samu_state_t *s,
    const samu_packet_t *query, samu_packet_t *reply)
{
    const
    samu_command_service_ccp_t *query_ccp = &query->data.service_ccp;
    samu_command_service_ccp_t *reply_ccp = &reply->data.service_ccp;

    reply_ccp->opcode = query_ccp->opcode;
    reply_ccp->status = query_ccp->status;
    uint32_t ccp_op = query_ccp->opcode >> 24;
    switch (ccp_op) {
    case CCP_OP_AES:
        samu_packet_ccp_aes(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_AES_INSITU:
        samu_packet_ccp_aes_insitu(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_XTS:
        samu_packet_ccp_xts(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_SHA:
        samu_packet_ccp_sha(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_RSA:
        samu_packet_ccp_rsa(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_PASS:
        samu_packet_ccp_pass(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_ECC:
        samu_packet_ccp_ecc(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_ZLIB:
        samu_packet_ccp_zlib(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_TRNG:
        samu_packet_ccp_trng(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_HMAC:
        samu_packet_ccp_hmac(s, query_ccp, reply_ccp);
        break;
    case CCP_OP_SNVS:
        samu_packet_ccp_snvs(s, query_ccp, reply_ccp);
        break;
    default:
        DPRINTF("Unknown SAMU CCP opcode: %d", ccp_op);
        assert(0);
    }
    return 0;
}

static uint32_t samu_packet_mailbox(samu_state_t *s,
    const samu_packet_t *query, samu_packet_t *reply)
{
    const
    samu_command_service_mailbox_t *query_mb = &query->data.service_mailbox;
    samu_command_service_mailbox_t *reply_mb = &reply->data.service_mailbox;
    uint32_t ret = MODULE_ERR_OK;

    reply_mb->unk_00 = query_mb->unk_00;
    reply_mb->module_id = query_mb->module_id;
    reply_mb->function_id = query_mb->function_id;

    switch (query_mb->module_id) {
    case AUTHID_PUP_MGR:
        if (!sbl_pupmgr_spawned()) {
            return -3; // TODO: Maybe this is just -ESRCH
        }
        switch (query_mb->function_id) {
        case PUPMGR_SM_DECRYPT_HEADER:
            ret = sbl_pupmgr_decrypt_header(s,
                (pupmgr_decrypt_header_t*)&query_mb->data,
                (pupmgr_decrypt_header_t*)&reply_mb->data);
            break;
        case PUPMGR_SM_DECRYPT_SEGMENT:
            ret = sbl_pupmgr_decrypt_segment(s,
                (pupmgr_decrypt_segment_t*)&query_mb->data,
                (pupmgr_decrypt_segment_t*)&reply_mb->data);
            break;
        case PUPMGR_SM_VERIFY_HEADER:
            ret = sbl_pupmgr_verify_header(s,
                (pupmgr_verify_header_t*)&query_mb->data,
                (pupmgr_verify_header_t*)&reply_mb->data);
            break;
        case PUPMGR_SM_EXIT:
            ret = sbl_pupmgr_exit(
                (pupmgr_exit_t*)&query_mb->data,
                (pupmgr_exit_t*)&reply_mb->data);
            break;
        default:
            DPRINTF("Unknown Function ID: 0x%X", query_mb->function_id);
        }
        break;
    case AUTHID_AUTH_MGR:
        switch (query_mb->function_id) {
        case AUTHMGR_SM_VERIFY_HEADER:
            ret = sbl_authmgr_verify_header(s,
                (authmgr_verify_header_t*)&query_mb->data,
                (authmgr_verify_header_t*)&reply_mb->data);
            break;
        case AUTHMGR_SM_LOAD_SELF_SEGMENT:
            ret = sbl_authmgr_load_self_segment(s,
                (authmgr_load_self_segment_t*)&query_mb->data,
                (authmgr_load_self_segment_t*)&reply_mb->data);
            break;
        case AUTHMGR_SM_LOAD_SELF_BLOCK:
            ret = sbl_authmgr_load_self_block(s,
                (authmgr_load_self_block_t*)&query_mb->data,
                (authmgr_load_self_block_t*)&reply_mb->data);
            break;
        case AUTHMGR_SM_INVOKE_CHECK:
            ret = sbl_authmgr_invoke_check(s,
                (authmgr_invoke_check_t*)&query_mb->data,
                (authmgr_invoke_check_t*)&reply_mb->data);
            break;
        case AUTHMGR_SM_IS_LOADABLE:
            ret = sbl_authmgr_is_loadable(s,
                (authmgr_is_loadable_t*)&query_mb->data,
                (authmgr_is_loadable_t*)&reply_mb->data);
            break;
        default:
            DPRINTF("Unknown Function ID: 0x%X", query_mb->function_id);
        }
        break;
    case AUTHID_IDATA_MGR:
        switch (query_mb->function_id) {
        default:
            DPRINTF("Unknown Function ID: 0x%X", query_mb->function_id);
        }
        break;
    case AUTHID_KEY_MGR:
        switch (query_mb->function_id) {
        default:
            DPRINTF("Unknown Function ID: 0x%X", query_mb->function_id);
        }
        break;
    default:
        DPRINTF("Unknown Module ID: 0x%llX", query_mb->module_id);
    }
    reply_mb->retval = ret;
    return 0;
}

static uint32_t samu_packet_rand(samu_state_t *s,
    const samu_packet_t *query, samu_packet_t *reply)
{
    const
    samu_command_service_rand_t *query_rand = &query->data.service_rand;
    samu_command_service_rand_t *reply_rand = &query->data.service_rand; // TODO: Why is the same address reused?

    qcrypto_random_bytes(reply_rand->data, 0x10, &error_fatal);
    return 0;
}

void liverpool_gc_samu_packet(samu_state_t *s,
    uint64_t query_addr, uint64_t reply_addr)
{
    uint64_t packet_length = 0x1000;
    samu_packet_t *query, *reply;
    hwaddr query_len = packet_length;
    hwaddr reply_len = packet_length;
    uint32_t status = 0;

    reply_addr = query_addr & 0xFFF00000; // TODO: Where does this address come from?
    query = (samu_packet_t*)address_space_map(
        &address_space_memory, query_addr, &query_len, true);
    reply = (samu_packet_t*)address_space_map(
        &address_space_memory, reply_addr, &reply_len, true);
    trace_samu_packet(query);

    memset(reply, 0, packet_length);
    reply->command = query->command;
    reply->message_id = query->message_id;
    reply->extended_msgs = query->extended_msgs;

    switch (query->command) {
    case SAMU_CMD_SERVICE_SPAWN:
        status = samu_packet_spawn(s, query, reply);
        break;
    case SAMU_CMD_SERVICE_CCP:
        status = samu_packet_ccp(s, query, reply);
        break;
    case SAMU_CMD_SERVICE_MAILBOX:
        status = samu_packet_mailbox(s, query, reply);
        break;
    case SAMU_CMD_SERVICE_RAND:
        status = samu_packet_rand(s, query, reply);
        break;
    default:
        printf("Unknown SAMU command %d\n", query->command);
    }
    reply->status = status;

    address_space_unmap(&address_space_memory, query, query_len, true, query_len);
    address_space_unmap(&address_space_memory, reply, reply_len, true, reply_len);
}

void liverpool_gc_samu_init(samu_state_t *s, uint64_t addr)
{
    int err;
    hwaddr length;
    samu_packet_t *packet;
    const char *blobs_filename = "crypto/blobs.zip";
    const char *secure_kernel_build =
        "secure kernel build: Sep 26 2017 ??:??:?? (r8963:release_branches/release_05.000)\n";

    length = 0x1000;
    packet = address_space_map(&address_space_memory, addr, &length, true);
    memset(packet, 0, length);
    samu_packet_io_write(s, packet, SAMU_CMD_IO_WRITE_FD_STDOUT,
        (char*)secure_kernel_build, strlen(secure_kernel_build));
    address_space_unmap(&address_space_memory, packet, length, true, length);

    blobs_zip = zip_open(blobs_filename, ZIP_RDONLY, &err);
    if (!blobs_zip) {
        printf("Could not open ZIP file %s due to error %d\n", blobs_filename, err);
        assert(0);
    }
}
