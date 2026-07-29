/*
 * Copyright 2026 Lens contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal first-party WFP connect-redirect callout. The driver is deliberately
 * fail-open: invalid configuration or an internal redirect failure permits the
 * original connection and increments a diagnostic counter.
 */
#include <initguid.h>
#include "lens_wfp.h"

typedef struct LENS_DRIVER_STATE {
    KSPIN_LOCK lock;
    LENS_WFP_CONFIG config;
    BOOLEAN active;
    UINT32 callout_v4;
    UINT32 callout_v6;
    HANDLE redirect_handle;
    volatile LONG64 redirected_connections;
    volatile LONG64 redirect_errors;
} LENS_DRIVER_STATE;

static LENS_DRIVER_STATE g_state;

static BOOLEAN
LensHeaderValid(_In_ const LENS_WFP_ABI_HEADER *header,
                _In_ uint16_t expected_size,
                _In_ uint32_t expected_operation)
{
    return header != NULL &&
           header->version == LENS_WFP_ABI_VERSION &&
           header->size == expected_size &&
           header->operation == expected_operation;
}

static void
LensReadConfig(_Out_ LENS_WFP_CONFIG *config, _Out_ BOOLEAN *active)
{
    KIRQL old_irql;
    KeAcquireSpinLock(&g_state.lock, &old_irql);
    RtlCopyMemory(config, &g_state.config, sizeof(*config));
    *active = g_state.active;
    KeReleaseSpinLock(&g_state.lock, old_irql);
}

static void
LensWriteConfig(_In_ const LENS_WFP_CONFIG *config, _In_ BOOLEAN active)
{
    KIRQL old_irql;
    KeAcquireSpinLock(&g_state.lock, &old_irql);
    RtlCopyMemory(&g_state.config, config, sizeof(*config));
    g_state.active = active;
    KeReleaseSpinLock(&g_state.lock, old_irql);
}

static void
LensDisable(void)
{
    LENS_WFP_CONFIG empty;
    RtlZeroMemory(&empty, sizeof(empty));
    LensWriteConfig(&empty, FALSE);
}

static NTSTATUS
LensRegisterCallout(_In_ PDEVICE_OBJECT device_object,
                    _In_ const GUID *key,
                    _Out_ UINT32 *callout_id)
{
    FWPS_CALLOUT1 callout;
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *key;
    callout.classifyFn = LensClassifyConnectRedirect;
    callout.notifyFn = LensNotify;
    return FwpsCalloutRegister1(device_object, &callout, callout_id);
}

static NTSTATUS
LensCreateControlDevice(_In_ WDFDRIVER driver, _Out_ WDFDEVICE *device)
{
    DECLARE_CONST_UNICODE_STRING(device_name, LENS_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symbolic_name, LENS_DOS_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(sddl,
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PWDFDEVICE_INIT init = NULL;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_IO_QUEUE_CONFIG queue_config;
    NTSTATUS status;

    init = WdfControlDeviceInitAllocate(driver, &sddl);
    if (init == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(init, LENS_WFP_DEVICE_TYPE);
    WdfDeviceInitSetCharacteristics(init, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetIoType(init, WdfDeviceIoBuffered);

    status = WdfDeviceInitAssignName(init, &device_name);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(init);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    status = WdfDeviceCreate(&init, &attributes, device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfDeviceCreateSymbolicLink(*device, &symbolic_name);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queue_config, WdfIoQueueDispatchSequential);
    queue_config.EvtIoDeviceControl = LensEvtIoDeviceControl;
    status = WdfIoQueueCreate(*device, &queue_config,
                              WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WdfControlFinishInitializing(*device);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT driver_object,
            _In_ PUNICODE_STRING registry_path)
{
    WDF_DRIVER_CONFIG driver_config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;
    WDFDEVICE device;
    NTSTATUS status;

    RtlZeroMemory(&g_state, sizeof(g_state));
    KeInitializeSpinLock(&g_state.lock);

    WDF_DRIVER_CONFIG_INIT(&driver_config, WDF_NO_EVENT_CALLBACK);
    driver_config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    driver_config.EvtDriverUnload = LensEvtDriverUnload;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfDriverCreate(driver_object, registry_path, &attributes,
                             &driver_config, &driver);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = LensCreateControlDevice(driver, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FwpsRedirectHandleCreate0(&LENS_WFP_PROVIDER_KEY, 0,
                                       &g_state.redirect_handle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = LensRegisterCallout(WdfDeviceWdmGetDeviceObject(device),
                                 &LENS_WFP_CALLOUT_V4_KEY,
                                 &g_state.callout_v4);
    if (!NT_SUCCESS(status)) {
        FwpsRedirectHandleDestroy0(g_state.redirect_handle);
        g_state.redirect_handle = NULL;
        return status;
    }

    status = LensRegisterCallout(WdfDeviceWdmGetDeviceObject(device),
                                 &LENS_WFP_CALLOUT_V6_KEY,
                                 &g_state.callout_v6);
    if (!NT_SUCCESS(status)) {
        FwpsCalloutUnregisterById0(g_state.callout_v4);
        g_state.callout_v4 = 0;
        FwpsRedirectHandleDestroy0(g_state.redirect_handle);
        g_state.redirect_handle = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

void
LensEvtDriverUnload(_In_ WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);
    LensDisable();
    if (g_state.callout_v6 != 0) {
        FwpsCalloutUnregisterById0(g_state.callout_v6);
    }
    if (g_state.callout_v4 != 0) {
        FwpsCalloutUnregisterById0(g_state.callout_v4);
    }
    if (g_state.redirect_handle != NULL) {
        FwpsRedirectHandleDestroy0(g_state.redirect_handle);
    }
}

void
LensEvtIoDeviceControl(_In_ WDFQUEUE queue,
                       _In_ WDFREQUEST request,
                       _In_ size_t output_length,
                       _In_ size_t input_length,
                       _In_ ULONG control_code)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t information = 0;
    UNREFERENCED_PARAMETER(queue);

    if (control_code == IOCTL_LENS_WFP_CONFIGURE) {
        LENS_WFP_CONFIG *config = NULL;
        size_t length = 0;
        status = WdfRequestRetrieveInputBuffer(
            request, sizeof(*config), (PVOID *)&config, &length);
        if (NT_SUCCESS(status) &&
            input_length == sizeof(*config) && length >= sizeof(*config) &&
            LensHeaderValid(&config->header, sizeof(*config),
                            LENS_WFP_OPERATION_CONFIGURE) &&
            config->proxy_pid != 0 && config->proxy_pid <= MAXULONG &&
            config->listen_port != 0 &&
            config->generation != 0 && config->session_nonce != 0 &&
            config->flags == 0) {
            LensWriteConfig(config, TRUE);
            status = STATUS_SUCCESS;
        } else if (NT_SUCCESS(status)) {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (control_code == IOCTL_LENS_WFP_DISABLE) {
        if (input_length == 0) {
            LensDisable();
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    } else if (control_code == IOCTL_LENS_WFP_STATUS) {
        LENS_WFP_STATUS *driver_status = NULL;
        LENS_WFP_CONFIG config;
        BOOLEAN active;
        size_t length = 0;
        status = WdfRequestRetrieveOutputBuffer(
            request, sizeof(*driver_status), (PVOID *)&driver_status, &length);
        if (NT_SUCCESS(status) && output_length >= sizeof(*driver_status) &&
            length >= sizeof(*driver_status)) {
            LensReadConfig(&config, &active);
            RtlZeroMemory(driver_status, sizeof(*driver_status));
            driver_status->header.version = LENS_WFP_ABI_VERSION;
            driver_status->header.size = sizeof(*driver_status);
            driver_status->header.operation = LENS_WFP_OPERATION_STATUS;
            driver_status->state = active ? 2u : 1u;
            driver_status->generation = config.generation;
            driver_status->redirected_connections =
                (LENS_UINT64)InterlockedCompareExchange64(
                    &g_state.redirected_connections, 0, 0);
            driver_status->redirect_errors =
                (LENS_UINT64)InterlockedCompareExchange64(
                    &g_state.redirect_errors, 0, 0);
            information = sizeof(*driver_status);
            status = STATUS_SUCCESS;
        }
    }

    WdfRequestCompleteWithInformation(request, status, information);
}

static BOOLEAN
LensConnectionFields(_In_ const FWPS_INCOMING_VALUES0 *values,
                     _Out_ UINT8 *protocol)
{
    if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
        *protocol = values->incomingValue[
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
        return TRUE;
    }
    if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) {
        *protocol = values->incomingValue[
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL].value.uint8;
        return TRUE;
    }
    return FALSE;
}

void NTAPI
LensClassifyConnectRedirect(
    _In_ const FWPS_INCOMING_VALUES0 *incoming_values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    _Inout_opt_ void *layer_data,
    _In_opt_ const void *classify_context,
    _In_ const FWPS_FILTER1 *filter,
    _In_ uint64_t flow_context,
    _Inout_ FWPS_CLASSIFY_OUT0 *classify_out)
{
    LENS_WFP_CONFIG config;
    LENS_WFP_REDIRECT_CONTEXT *context = NULL;
    FWPS_CONNECT_REQUEST0 *connect_request = NULL;
    UINT64 classify_handle = 0;
    UINT8 protocol = 0;
    UINT64 process_id = 0;
    BOOLEAN active;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((classify_out->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }
    classify_out->actionType = FWP_ACTION_PERMIT;

    LensReadConfig(&config, &active);
    if (!active || classify_context == NULL ||
        !LensConnectionFields(incoming_values, &protocol) ||
        protocol != IPPROTO_TCP) {
        return;
    }

    if (FWPS_IS_METADATA_FIELD_PRESENT(metadata,
                                       FWPS_METADATA_FIELD_PROCESS_ID)) {
        process_id = metadata->processId;
    }
    if (process_id == 0 || process_id == config.proxy_pid) {
        return;
    }

    status = FwpsAcquireClassifyHandle0((PVOID)classify_context, 0,
                                        &classify_handle);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_state.redirect_errors);
        return;
    }

    status = FwpsAcquireWritableLayerDataPointer0(
        classify_handle, filter->filterId, 0,
        (PVOID *)&connect_request, classify_out);
    if (!NT_SUCCESS(status) || connect_request == NULL) {
        FwpsReleaseClassifyHandle0(classify_handle);
        InterlockedIncrement64(&g_state.redirect_errors);
        return;
    }

    context = (LENS_WFP_REDIRECT_CONTEXT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*context), LENS_POOL_TAG);
    if (context == NULL) {
        FwpsApplyModifiedLayerData0(classify_handle, connect_request, 0);
        FwpsReleaseClassifyHandle0(classify_handle);
        InterlockedIncrement64(&g_state.redirect_errors);
        return;
    }
    RtlZeroMemory(context, sizeof(*context));
    context->header.version = LENS_WFP_ABI_VERSION;
    context->header.size = sizeof(*context);
    context->header.operation = LENS_WFP_OPERATION_REDIRECT_CONTEXT;
    context->protocol = protocol;
    context->process_id = process_id;
    context->generation = config.generation;

    if (incoming_values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
        SOCKADDR_IN *original =
            (SOCKADDR_IN *)&connect_request->remoteAddressAndPort;
        SOCKADDR_IN *redirect =
            (SOCKADDR_IN *)&connect_request->remoteAddressAndPort;
        context->address_family = AF_INET;
        context->destination_port_network_order = original->sin_port;
        RtlCopyMemory(context->destination_address,
                      &original->sin_addr, sizeof(original->sin_addr));
        redirect->sin_family = AF_INET;
        redirect->sin_addr.s_addr = RtlUlongByteSwap(INADDR_LOOPBACK);
        redirect->sin_port = RtlUshortByteSwap(config.listen_port);
    } else {
        SOCKADDR_IN6 *original =
            (SOCKADDR_IN6 *)&connect_request->remoteAddressAndPort;
        SOCKADDR_IN6 *redirect =
            (SOCKADDR_IN6 *)&connect_request->remoteAddressAndPort;
        static const IN6_ADDR loopback = IN6ADDR_LOOPBACK_INIT;
        context->address_family = AF_INET6;
        context->destination_port_network_order = original->sin6_port;
        RtlCopyMemory(context->destination_address,
                      &original->sin6_addr, sizeof(original->sin6_addr));
        redirect->sin6_family = AF_INET6;
        redirect->sin6_addr = loopback;
        redirect->sin6_port = RtlUshortByteSwap(config.listen_port);
    }

    connect_request->localRedirectHandle = g_state.redirect_handle;
    connect_request->localRedirectTargetPID = (UINT32)config.proxy_pid;
    connect_request->localRedirectContext = context;
    connect_request->localRedirectContextSize = sizeof(*context);

    FwpsApplyModifiedLayerData0(classify_handle, connect_request, 0);
    FwpsReleaseClassifyHandle0(classify_handle);
    classify_out->actionType = FWP_ACTION_PERMIT;
    if ((filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) != 0) {
        classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    InterlockedIncrement64(&g_state.redirected_connections);
}

NTSTATUS NTAPI
LensNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notify_type,
           _In_ const GUID *filter_key,
           _Inout_ FWPS_FILTER1 *filter)
{
    UNREFERENCED_PARAMETER(notify_type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}
