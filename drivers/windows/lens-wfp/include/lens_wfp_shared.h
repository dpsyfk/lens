/*
 * Copyright 2026 Lens contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pointer-free ABI shared by the Lens WFP driver and user-space controller.
 * Every record is fixed width, little-endian except network ports and address
 * bytes, and begins with a versioned header.
 */
#pragma once

#if defined(_KERNEL_MODE)
#include <devioctl.h>
typedef UCHAR LENS_UINT8;
typedef USHORT LENS_UINT16;
typedef ULONG LENS_UINT32;
typedef ULONGLONG LENS_UINT64;
#else
#include <stdint.h>
#include <winioctl.h>
typedef uint8_t LENS_UINT8;
typedef uint16_t LENS_UINT16;
typedef uint32_t LENS_UINT32;
typedef uint64_t LENS_UINT64;
#endif

#define LENS_WFP_ABI_VERSION ((LENS_UINT16)1)
#define LENS_WFP_DEVICE_TYPE ((LENS_UINT32)0x8337)

#define LENS_WFP_OPERATION_CONFIGURE ((LENS_UINT32)1)
#define LENS_WFP_OPERATION_DISABLE ((LENS_UINT32)2)
#define LENS_WFP_OPERATION_STATUS ((LENS_UINT32)3)
#define LENS_WFP_OPERATION_REDIRECT_CONTEXT ((LENS_UINT32)4)

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
    LENS_UINT16 version;
    LENS_UINT16 size;
    LENS_UINT32 operation;
} LENS_WFP_ABI_HEADER;

typedef struct LENS_WFP_CONFIG {
    LENS_WFP_ABI_HEADER header;
    LENS_UINT64 proxy_pid;
    LENS_UINT16 listen_port;
    LENS_UINT16 flags;
    LENS_UINT32 generation;
    LENS_UINT64 session_nonce;
} LENS_WFP_CONFIG;

typedef struct LENS_WFP_STATUS {
    LENS_WFP_ABI_HEADER header;
    LENS_UINT32 state;
    LENS_UINT32 flags;
    LENS_UINT64 generation;
    LENS_UINT64 redirected_connections;
    LENS_UINT64 redirect_errors;
} LENS_WFP_STATUS;

typedef struct LENS_WFP_REDIRECT_CONTEXT {
    LENS_WFP_ABI_HEADER header;
    LENS_UINT16 address_family;
    LENS_UINT8 protocol;
    LENS_UINT8 flags;
    LENS_UINT16 destination_port_network_order;
    LENS_UINT16 reserved;
    LENS_UINT8 destination_address[16];
    LENS_UINT64 process_id;
    LENS_UINT64 generation;
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
