/*
 * Copyright 2026 Lens contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pointer-free ABI shared by the Lens WFP driver and user-space controller.
 * Every record is fixed width, little-endian except network ports and address
 * bytes, and begins with a versioned header.
 */
#pragma once

#include <stdint.h>

#if defined(_KERNEL_MODE)
#include <devioctl.h>
#else
#include <winioctl.h>
#endif

#define LENS_WFP_ABI_VERSION ((uint16_t)1)
#define LENS_WFP_DEVICE_TYPE ((uint32_t)0x8337)

#define LENS_WFP_OPERATION_CONFIGURE ((uint32_t)1)
#define LENS_WFP_OPERATION_DISABLE ((uint32_t)2)
#define LENS_WFP_OPERATION_STATUS ((uint32_t)3)
#define LENS_WFP_OPERATION_REDIRECT_CONTEXT ((uint32_t)4)

#define IOCTL_LENS_WFP_CONFIGURE                                                \
    CTL_CODE(LENS_WFP_DEVICE_TYPE, 0x900, METHOD_BUFFERED,                      \
             FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LENS_WFP_DISABLE                                                  \
    CTL_CODE(LENS_WFP_DEVICE_TYPE, 0x901, METHOD_BUFFERED,                      \
             FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LENS_WFP_STATUS                                                   \
    CTL_CODE(LENS_WFP_DEVICE_TYPE, 0x902, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(push, 1)

typedef struct LENS_WFP_ABI_HEADER {
    uint16_t version;
    uint16_t size;
    uint32_t operation;
} LENS_WFP_ABI_HEADER;

typedef struct LENS_WFP_CONFIG {
    LENS_WFP_ABI_HEADER header;
    uint64_t proxy_pid;
    uint16_t listen_port;
    uint16_t flags;
    uint32_t generation;
    uint64_t session_nonce;
} LENS_WFP_CONFIG;

typedef struct LENS_WFP_STATUS {
    LENS_WFP_ABI_HEADER header;
    uint32_t state;
    uint32_t flags;
    uint64_t generation;
    uint64_t redirected_connections;
    uint64_t redirect_errors;
} LENS_WFP_STATUS;

typedef struct LENS_WFP_REDIRECT_CONTEXT {
    LENS_WFP_ABI_HEADER header;
    uint16_t address_family;
    uint8_t protocol;
    uint8_t flags;
    uint16_t destination_port_network_order;
    uint16_t reserved;
    uint8_t destination_address[16];
    uint64_t process_id;
    uint64_t generation;
} LENS_WFP_REDIRECT_CONTEXT;

#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(LENS_WFP_ABI_HEADER) == 8, "Lens ABI header changed");
static_assert(sizeof(LENS_WFP_CONFIG) == 32, "Lens config ABI changed");
static_assert(sizeof(LENS_WFP_STATUS) == 40, "Lens status ABI changed");
static_assert(sizeof(LENS_WFP_REDIRECT_CONTEXT) == 48,
              "Lens redirect context ABI changed");
#else
C_ASSERT(sizeof(LENS_WFP_ABI_HEADER) == 8);
C_ASSERT(sizeof(LENS_WFP_CONFIG) == 32);
C_ASSERT(sizeof(LENS_WFP_STATUS) == 40);
C_ASSERT(sizeof(LENS_WFP_REDIRECT_CONTEXT) == 48);
#endif
