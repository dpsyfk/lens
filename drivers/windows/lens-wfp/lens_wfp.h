/* Copyright 2026 Lens contributors. SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <ws2def.h>
#include <ws2ipdef.h>

#include "include/lens_wfp_shared.h"

#define LENS_POOL_TAG 'sneL'
#define LENS_DEVICE_NAME L"\\Device\\LensWfp"
#define LENS_DOS_DEVICE_NAME L"\\DosDevices\\LensWfp"

/* Stable product GUIDs. Changing these requires an explicit migration. */
DEFINE_GUID(LENS_WFP_PROVIDER_KEY,
            0x5623e61b, 0xb8d4, 0x4c98, 0xa3, 0x79, 0x6f, 0xee, 0x58, 0xf4,
            0x2c, 0x10);
DEFINE_GUID(LENS_WFP_CALLOUT_V4_KEY,
            0xc3aefc98, 0xe967, 0x45bf, 0x9c, 0xda, 0x86, 0xb6, 0xd8, 0x43,
            0x69, 0xf4);
DEFINE_GUID(LENS_WFP_CALLOUT_V6_KEY,
            0x6c557e87, 0x754d, 0x4dc9, 0x86, 0xcf, 0xc2, 0x13, 0x1c, 0xe8,
            0xc0, 0xd5);

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD LensEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL LensEvtIoDeviceControl;

void NTAPI LensClassifyConnectRedirect(
    _In_ const FWPS_INCOMING_VALUES0 *incoming_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    _Inout_opt_ void *layer_data,
    _In_opt_ const void *classify_context,
    _In_ const FWPS_FILTER1 *filter,
    _In_ uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT0 *classify_out);

NTSTATUS NTAPI LensNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notify_type,
    _In_ const GUID *filter_key,
    _Inout_ FWPS_FILTER1 *filter);
