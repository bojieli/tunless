#include <initguid.h>
#include "tunless.h"

static PDEVICE_OBJECT Device;
static HANDLE Engine;
static HANDLE RedirectHandle;
static UINT32 Callout4;
static UINT32 Callout6;
static TUNLESS_CONFIG Config;
static TUNLESS_CONFIG ActiveConfig;
static FAST_MUTEX ControlLock;
static KSPIN_LOCK ConfigLock;

static BOOLEAN IsValidConfig(const TUNLESS_CONFIG *config)
{
    SIZE_T index;

    if (config->ProcessId == 0 || config->ProcessId > MAXLONG || config->Port == 0) {
        return FALSE;
    }
    for (index = 0; index < RTL_NUMBER_OF(config->Reserved); ++index) {
        if (config->Reserved[index] != 0) {
            return FALSE;
        }
    }
    return TRUE;
}

static TUNLESS_CONFIG ReadActiveConfig(void)
{
    TUNLESS_CONFIG config;
    KIRQL oldIrql;

    KeAcquireSpinLock(&ConfigLock, &oldIrql);
    config = ActiveConfig;
    KeReleaseSpinLock(&ConfigLock, oldIrql);
    return config;
}

static void PublishActiveConfig(const TUNLESS_CONFIG *config)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&ConfigLock, &oldIrql);
    if (config == NULL) {
        RtlZeroMemory(&ActiveConfig, sizeof(ActiveConfig));
    } else {
        ActiveConfig = *config;
    }
    KeReleaseSpinLock(&ConfigLock, oldIrql);
}

static void NTAPI Classify(
    const FWPS_INCOMING_VALUES0 *values,
    const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST0 *request = NULL;
    TUNLESS_REDIRECT_CONTEXT *redirect = NULL;
    FWPS_CONNECTION_REDIRECT_STATE state;
    NTSTATUS status;
    UINT16 appField;
    const FWP_BYTE_BLOB *appId;
    SIZE_T appBytes;
    const FWPS_CONNECT_REQUEST0 *previous;
    TUNLESS_CONFIG config;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    if (values == NULL || metadata == NULL || classifyContext == NULL || filter == NULL || classifyOut == NULL ||
        !(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;
    config = ReadActiveConfig();
    if (config.Port == 0 ||
        (values->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 &&
         values->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) ||
        !(metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) ||
        metadata->processId == 0 || metadata->processId > MAXLONG ||
        metadata->processId == config.ProcessId) {
        return;
    }

    if (metadata->redirectRecords != NULL) {
        state = FwpsQueryConnectionRedirectState0(metadata->redirectRecords, RedirectHandle, NULL);
        if (state == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
            state == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) {
            return;
        }
    }

    status = FwpsAcquireClassifyHandle0((void *)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        return;
    }
    status = FwpsAcquireWritableLayerDataPointer0(
        classifyHandle,
        filter->filterId,
        0,
        (void **)&request,
        classifyOut);
    if (!NT_SUCCESS(status) || request == NULL) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    /* Do not stack another local proxy on top of a different redirector. */
    for (previous = request->previousVersion;
         previous != NULL;
         previous = previous->previousVersion) {
        if (previous->modifierFilterId != filter->filterId &&
            previous->localRedirectHandle != NULL) {
            FwpsApplyModifiedLayerData0(classifyHandle, request, 0);
            FwpsReleaseClassifyHandle0(classifyHandle);
            return;
        }
    }

    redirect = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*redirect), 'LnuT');
    if (redirect == NULL) {
        FwpsApplyModifiedLayerData0(classifyHandle, request, 0);
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }
    RtlZeroMemory(redirect, sizeof(*redirect));
    RtlCopyMemory(&redirect->Original, &request->remoteAddressAndPort, sizeof(SOCKADDR_STORAGE));
    redirect->ProcessId = metadata->processId;

    appField = values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4
        ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID
        : FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID;
    if (values->incomingValue[appField].value.type == FWP_BYTE_BLOB_TYPE) {
        appId = values->incomingValue[appField].value.byteBlob;
        if (appId != NULL && appId->data != NULL) {
            appBytes = min((SIZE_T)appId->size, sizeof(redirect->AppId) - sizeof(WCHAR));
            appBytes -= appBytes % sizeof(WCHAR);
            RtlCopyMemory(redirect->AppId, appId->data, appBytes);
        }
    }

    RtlZeroMemory(&request->remoteAddressAndPort, sizeof(request->remoteAddressAndPort));
    if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
        SOCKADDR_IN *target = (SOCKADDR_IN *)&request->remoteAddressAndPort;
        target->sin_family = AF_INET;
        target->sin_addr.S_un.S_addr = RtlUlongByteSwap(0x7f000001);
        target->sin_port = RtlUshortByteSwap(config.Port);
    } else {
        SOCKADDR_IN6 *target = (SOCKADDR_IN6 *)&request->remoteAddressAndPort;
        target->sin6_family = AF_INET6;
        IN6_SET_ADDR_LOOPBACK(&target->sin6_addr);
        target->sin6_port = RtlUshortByteSwap(config.Port);
    }
    request->localRedirectHandle = RedirectHandle;
    request->localRedirectTargetPID = (DWORD)config.ProcessId;
    request->localRedirectContext = redirect;
    request->localRedirectContextSize = sizeof(*redirect);

    FwpsApplyModifiedLayerData0(classifyHandle, request, 0);
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    FwpsReleaseClassifyHandle0(classifyHandle);
}

static NTSTATUS NTAPI Notify(
    FWPS_CALLOUT_NOTIFY_TYPE type,
    const GUID *filterKey,
    FWPS_FILTER1 *filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static void StopLocked(void)
{
    PublishActiveConfig(NULL);
    if (Engine != NULL) {
        FwpmEngineClose0(Engine);
        Engine = NULL;
    }
    RtlZeroMemory(&Config, sizeof(Config));
}

static void Stop(void)
{
    ExAcquireFastMutex(&ControlLock);
    StopLocked();
    ExReleaseFastMutex(&ControlLock);
}

static NTSTATUS AddObjectsLocked(void)
{
    FWPM_SESSION0 session = {0};
    FWPM_SUBLAYER0 sublayer = {0};
    const GUID *layers[2] = {
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6
    };
    const GUID *keys[2] = {&TUNLESS_CALLOUT_V4, &TUNLESS_CALLOUT_V6};
    NTSTATUS status;
    int index;

    if (Engine != NULL) {
        return STATUS_DEVICE_BUSY;
    }
    if (!IsValidConfig(&Config)) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &Engine);
    if (!NT_SUCCESS(status)) {
        Engine = NULL;
        return status;
    }
    status = FwpmTransactionBegin0(Engine, 0);
    if (!NT_SUCCESS(status)) {
        StopLocked();
        return status;
    }

    sublayer.subLayerKey = TUNLESS_SUBLAYER;
    sublayer.displayData.name = L"tunless";
    sublayer.weight = 0x100;
    status = FwpmSubLayerAdd0(Engine, &sublayer, NULL);
    if (!NT_SUCCESS(status)) {
        goto abort;
    }
    for (index = 0; index < 2; ++index) {
        FWPM_CALLOUT0 callout = {0};
        FWPM_FILTER0 filter = {0};
        FWPM_FILTER_CONDITION0 protocol = {0};

        callout.calloutKey = *keys[index];
        callout.displayData.name = L"tunless connect redirect";
        callout.applicableLayer = *layers[index];
        status = FwpmCalloutAdd0(Engine, &callout, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            goto abort;
        }

        protocol.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        protocol.matchType = FWP_MATCH_EQUAL;
        protocol.conditionValue.type = FWP_UINT8;
        protocol.conditionValue.uint8 = IPPROTO_TCP;
        filter.displayData.name = L"tunless dynamic TCP redirect";
        filter.layerKey = *layers[index];
        filter.subLayerKey = TUNLESS_SUBLAYER;
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = *keys[index];
        filter.weight.type = FWP_EMPTY;
        filter.numFilterConditions = 1;
        filter.filterCondition = &protocol;
        status = FwpmFilterAdd0(Engine, &filter, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            goto abort;
        }
    }
    /* Publish before commit so newly activated filters never see an empty config. */
    PublishActiveConfig(&Config);
    status = FwpmTransactionCommit0(Engine);
    if (!NT_SUCCESS(status)) {
        StopLocked();
    }
    return status;

abort:
    FwpmTransactionAbort0(Engine);
    StopLocked();
    return status;
}

static NTSTATUS Dispatch(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    TUNLESS_CONFIG config;

    UNREFERENCED_PARAMETER(device);
    switch (stack->MajorFunction) {
    case IRP_MJ_DEVICE_CONTROL:
        ExAcquireFastMutex(&ControlLock);
        if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TUNLESS_CONFIG &&
            stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(config) &&
            stack->Parameters.DeviceIoControl.OutputBufferLength == 0 &&
            Engine == NULL) {
            RtlCopyMemory(&config, irp->AssociatedIrp.SystemBuffer, sizeof(config));
            if (IsValidConfig(&config)) {
                Config = config;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
        } else if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TUNLESS_START &&
                   stack->Parameters.DeviceIoControl.InputBufferLength == 0 &&
                   stack->Parameters.DeviceIoControl.OutputBufferLength == 0) {
            status = AddObjectsLocked();
        } else {
            status = STATUS_INVALID_DEVICE_REQUEST;
        }
        ExReleaseFastMutex(&ControlLock);
        break;
    case IRP_MJ_CLEANUP:
        Stop();
        break;
    default:
        break;
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static void Unload(PDRIVER_OBJECT driver)
{
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\Tunless");
    NTSTATUS status;

    Stop();
    if (Callout6 != 0) {
        status = FwpsCalloutUnregisterById0(Callout6);
        NT_ASSERT(NT_SUCCESS(status));
        Callout6 = 0;
    }
    if (Callout4 != 0) {
        status = FwpsCalloutUnregisterById0(Callout4);
        NT_ASSERT(NT_SUCCESS(status));
        Callout4 = 0;
    }
    if (RedirectHandle != NULL) {
        FwpsRedirectHandleDestroy0(RedirectHandle);
        RedirectHandle = NULL;
    }
    IoDeleteSymbolicLink(&link);
    IoDeleteDevice(driver->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\Tunless");
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\Tunless");
    UNICODE_STRING security = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    FWPS_CALLOUT1 callout = {0};
    NTSTATUS status;

    UNREFERENCED_PARAMETER(registryPath);
    ExInitializeFastMutex(&ControlLock);
    KeInitializeSpinLock(&ConfigLock);
    status = IoCreateDeviceSecure(
        driver,
        0,
        &name,
        FILE_DEVICE_NETWORK,
        0,
        TRUE,
        &security,
        &TUNLESS_DEVICE_CLASS,
        &Device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Device->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(Device);
        return status;
    }
    driver->DriverUnload = Unload;
    driver->MajorFunction[IRP_MJ_CREATE] = Dispatch;
    driver->MajorFunction[IRP_MJ_CLOSE] = Dispatch;
    driver->MajorFunction[IRP_MJ_CLEANUP] = Dispatch;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch;

    callout.classifyFn = Classify;
    callout.notifyFn = Notify;
    callout.calloutKey = TUNLESS_CALLOUT_V4;
    status = FwpsCalloutRegister1(Device, &callout, &Callout4);
    if (!NT_SUCCESS(status)) {
        Unload(driver);
        return status;
    }
    callout.calloutKey = TUNLESS_CALLOUT_V6;
    status = FwpsCalloutRegister1(Device, &callout, &Callout6);
    if (!NT_SUCCESS(status)) {
        Unload(driver);
        return status;
    }
    status = FwpsRedirectHandleCreate0(&TUNLESS_SUBLAYER, 0, &RedirectHandle);
    if (!NT_SUCCESS(status)) {
        Unload(driver);
        return status;
    }
    Device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
