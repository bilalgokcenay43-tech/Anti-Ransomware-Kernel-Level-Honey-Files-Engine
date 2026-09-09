/*
 * ============================================================================
 * Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
 * Modül    : kernel/chronos_minifilter.c
 * Açıklama : Windows Filtering Manager (FLTMGR) mimarisine uygun MiniFilter
 *            sürücü şablonu. IRP_MJ_CREATE, IRP_MJ_WRITE ve
 *            IRP_MJ_SET_INFORMATION (rename/delete) I/O işlemlerini pre-op
 *            callback'lerle keser; telemetriyi user-mode EDR Core'a
 *            FilterConnectCommunicationPort / FltSendMessage altyapısı ile
 *            iletir.
 *
 * Derleme  : Windows Driver Kit (WDK) + Visual Studio gerektirir.
 *            Üretim ortamında EV Code Signing sertifikası ile imzalanmalıdır.
 *
 *   cl.exe (WDK) build komutu (x64 kernel modu):
 *     msbuild ChronosMinifilter.vcxproj /p:Configuration=Release /p:Platform=x64
 *
 *   Test ortamında yükleme (Test Signing etkin olmalı):
 *     bcdedit /set testsigning on
 *     sc create ChronosMF binPath= "%SystemRoot%\System32\drivers\chronos_mf.sys" type= kernel
 *     sc start ChronosMF
 *
 * Uyarı    : İmzasız sürücüler modern Windows (8+) sistemlerde Secure Boot
 *            nedeniyle varsayılan olarak yüklenmez.
 * ============================================================================
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

/* --------------------------------------------------------------------------
 * Sürücü Sabitleri
 * -------------------------------------------------------------------------- */
#define CHRONOS_DRIVER_NAME         L"ChronosMinifilter"
#define CHRONOS_PORT_NAME           L"\\ChronosEDRPort"
#define CHRONOS_MAX_CONNECTIONS     1
#define CHRONOS_MSG_BUFFER_SIZE     4096
#define CHRONOS_TAG                 'CHRN'

/* Önem derecesine göre log makrosu */
#define CHRONOS_LOG(level, fmt, ...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, level, "[ChronosMF] " fmt "\n", ##__VA_ARGS__))

/* --------------------------------------------------------------------------
 * User-Mode İletişim Mesaj Yapısı
 *
 * Bu yapı filter port üzerinden user-mode'a gönderilir.
 * Python tarafında ctypes.Structure ile eşleştirilir.
 * -------------------------------------------------------------------------- */
#pragma pack(push, 1)
typedef struct _CHRONOS_EVENT_MSG {
    ULONG       EventType;          /* 1=CREATE, 2=WRITE, 3=RENAME, 4=DELETE  */
    ULONG       Pid;                /* Tetikleyen sürecin PID'i                */
    ULONG       Tid;                /* Thread ID                               */
    LONGLONG    FileSize;           /* Dosya boyutu (bayt)                     */
    LONGLONG    Timestamp;          /* KeQuerySystemTime() değeri              */
    WCHAR       FilePath[512];      /* Hedef dosyanın tam yolu                 */
    WCHAR       ProcessName[64];    /* Tetikleyen sürecin adı                  */
} CHRONOS_EVENT_MSG, *PCHRONOS_EVENT_MSG;
#pragma pack(pop)

/* --------------------------------------------------------------------------
 * Global Sürücü Durumu
 * -------------------------------------------------------------------------- */
typedef struct _CHRONOS_DRIVER_DATA {
    PFILTER_DRIVER_CONTEXT  FilterHandle;   /* FltRegisterFilter'dan döner     */
    PFLT_PORT               ServerPort;     /* FltCreateCommunicationPort portu */
    PFLT_PORT               ClientPort;     /* Bağlanan user-mode istemci portu */
} CHRONOS_DRIVER_DATA, *PCHRONOS_DRIVER_DATA;

static CHRONOS_DRIVER_DATA g_ChronosData = { 0 };

/* --------------------------------------------------------------------------
 * İleri Bildirimler (Forward Declarations)
 * -------------------------------------------------------------------------- */
DRIVER_UNLOAD                   ChronosDriverUnload;
NTSTATUS                        ChronosInstanceSetup(
                                    _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                    _In_ DEVICE_TYPE VolumeDeviceType,
                                    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
FLT_PREOP_CALLBACK_STATUS       ChronosPreCreate(
                                    _Inout_ PFLT_CALLBACK_DATA Data,
                                    _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS       ChronosPreWrite(
                                    _Inout_ PFLT_CALLBACK_DATA Data,
                                    _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS       ChronosPreSetInfo(
                                    _Inout_ PFLT_CALLBACK_DATA Data,
                                    _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
NTSTATUS                        ChronosPortConnect(
                                    _In_ PFLT_PORT ClientPort,
                                    _In_opt_ PVOID ServerPortCookie,
                                    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                                    _In_ ULONG SizeOfContext,
                                    _Outptr_result_maybenull_ PVOID *ConnectionCookie);
VOID                            ChronosPortDisconnect(
                                    _In_opt_ PVOID ConnectionCookie);

/* --------------------------------------------------------------------------
 * FltMgr Callback Kayıt Tablosu
 * -------------------------------------------------------------------------- */
static const FLT_OPERATION_REGISTRATION g_ChronosCallbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        ChronosPreCreate,
        NULL
    },
    {
        IRP_MJ_WRITE,
        0,
        ChronosPreWrite,
        NULL
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        ChronosPreSetInfo,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

/* --------------------------------------------------------------------------
 * FltMgr Kayıt Tanımlayıcısı
 * -------------------------------------------------------------------------- */
static const FLT_REGISTRATION g_ChronosRegistration = {
    sizeof(FLT_REGISTRATION),           /* Yapı boyutu */
    FLT_REGISTRATION_VERSION,           /* Versiyon    */
    0,                                  /* Flags       */
    NULL,                               /* Context     */
    g_ChronosCallbacks,                 /* Callbacks   */
    ChronosDriverUnload,                /* Unload      */
    ChronosInstanceSetup,               /* InstanceSetup */
    NULL,                               /* InstanceQueryTeardown */
    NULL,                               /* InstanceTeardownStart */
    NULL,                               /* InstanceTeardownComplete */
    NULL, NULL, NULL
};

/* ============================================================================
 * Yardımcı: Mesajı User-Mode'a Gönder
 * ============================================================================ */
static VOID
ChronosSendEventToUserMode(
    _In_ ULONG      EventType,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
)
{
    CHRONOS_EVENT_MSG   msg     = { 0 };
    LARGE_INTEGER       replyTimeout;
    ULONG               replyLen = 0;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS            status;

    /* User-mode istemci bağlı değilse hiçbir şey yapma */
    if (!g_ChronosData.ClientPort) return;

    msg.EventType   = EventType;
    msg.Pid         = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    msg.Tid         = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

    KeQuerySystemTime((PLARGE_INTEGER)&msg.Timestamp);

    /* Dosya adını çöz */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status) && nameInfo->Name.Length > 0) {
            ULONG copyLen = min(
                nameInfo->Name.Length,
                (ULONG)(sizeof(msg.FilePath) - sizeof(WCHAR))
            );
            RtlCopyMemory(msg.FilePath, nameInfo->Name.Buffer, copyLen);
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    /* Süreç adını al */
    {
        PEPROCESS proc = PsGetCurrentProcess();
        if (proc) {
            PUCHAR imgName = PsGetProcessImageFileName(proc);
            if (imgName) {
                /* ASCII → Unicode dönüşümü (basit) */
                ANSI_STRING ansi;
                UNICODE_STRING uni;
                RtlInitAnsiString(&ansi, (PCSZ)imgName);
                uni.Buffer      = msg.ProcessName;
                uni.MaximumLength = sizeof(msg.ProcessName);
                RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
            }
        }
    }

    /* Dosya boyutunu al */
    {
        FILE_STANDARD_INFORMATION stdInfo;
        if (NT_SUCCESS(FltQueryInformationFile(
                FltObjects->Instance,
                FltObjects->FileObject,
                &stdInfo,
                sizeof(stdInfo),
                FileStandardInformation,
                NULL)))
        {
            msg.FileSize = stdInfo.EndOfFile.QuadPart;
        }
    }

    replyTimeout.QuadPart = -10000LL * 500;  /* 500 ms zaman aşımı */

    /* Mesajı gönder (engelleyici değil, kısa timeout ile) */
    FltSendMessage(
        g_ChronosData.FilterHandle,
        &g_ChronosData.ClientPort,
        &msg,
        sizeof(msg),
        NULL,
        &replyLen,
        &replyTimeout
    );
}

/* ============================================================================
 * Pre-Operation Callback: IRP_MJ_CREATE
 * ============================================================================ */
FLT_PREOP_CALLBACK_STATUS
ChronosPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    /* Yalnızca yazma niyetiyle açılan dosyaları filtrele */
    if (Data->Iopb->Parameters.Create.SecurityContext) {
        ULONG desiredAccess =
            Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        if (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE)) {
            ChronosSendEventToUserMode(1, Data, FltObjects); /* EventType=CREATE */
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================================================
 * Pre-Operation Callback: IRP_MJ_WRITE
 * ============================================================================ */
FLT_PREOP_CALLBACK_STATUS
ChronosPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    ChronosSendEventToUserMode(2, Data, FltObjects); /* EventType=WRITE */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================================================
 * Pre-Operation Callback: IRP_MJ_SET_INFORMATION (Rename / Delete)
 * ============================================================================ */
FLT_PREOP_CALLBACK_STATUS
ChronosPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    FILE_INFORMATION_CLASS fileInfoClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (fileInfoClass == FileDispositionInformation ||
        fileInfoClass == FileDispositionInformationEx)
    {
        ChronosSendEventToUserMode(4, Data, FltObjects); /* EventType=DELETE */
    }
    else if (fileInfoClass == FileRenameInformation ||
             fileInfoClass == FileRenameInformationEx)
    {
        ChronosSendEventToUserMode(3, Data, FltObjects); /* EventType=RENAME */
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================================================
 * İletişim Port Callback'leri
 * ============================================================================ */
NTSTATUS
ChronosPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    g_ChronosData.ClientPort = ClientPort;
    CHRONOS_LOG(DPFLTR_TRACE_LEVEL, "User-mode EDR Core bağlandı.");
    return STATUS_SUCCESS;
}

VOID
ChronosPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g_ChronosData.FilterHandle, &g_ChronosData.ClientPort);
    g_ChronosData.ClientPort = NULL;
    CHRONOS_LOG(DPFLTR_TRACE_LEVEL, "User-mode EDR Core bağlantısı kesildi.");
}

/* ============================================================================
 * Instance Setup Callback
 * ============================================================================ */
NTSTATUS
ChronosInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    /* Yalnızca NTFS hacimlerine bağlan */
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    return STATUS_SUCCESS;
}

/* ============================================================================
 * Sürücü Unload
 * ============================================================================ */
VOID
ChronosDriverUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_ChronosData.ServerPort) {
        FltCloseCommunicationPort(g_ChronosData.ServerPort);
    }
    if (g_ChronosData.FilterHandle) {
        FltUnregisterFilter(g_ChronosData.FilterHandle);
    }

    CHRONOS_LOG(DPFLTR_TRACE_LEVEL, "Chronos MiniFilter driver kaldırıldı.");
}

/* ============================================================================
 * DriverEntry — Sürücü Giriş Noktası
 * ============================================================================ */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS                    status;
    OBJECT_ATTRIBUTES           oa;
    UNICODE_STRING              portName;
    PSECURITY_DESCRIPTOR        sd = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    CHRONOS_LOG(DPFLTR_TRACE_LEVEL, "Chronos MiniFilter surucusu baslatiliyor...");

    /* 1. Filter kaydı */
    status = FltRegisterFilter(
        DriverObject,
        &g_ChronosRegistration,
        (PFLT_FILTER *)&g_ChronosData.FilterHandle
    );
    if (!NT_SUCCESS(status)) {
        CHRONOS_LOG(DPFLTR_ERROR_LEVEL, "FltRegisterFilter basarisiz: 0x%08X", status);
        return status;
    }

    /* 2. User-mode iletişim portunun güvenlik tanımlayıcısı */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) goto cleanup;

    RtlInitUnicodeString(&portName, CHRONOS_PORT_NAME);
    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        sd
    );

    /* 3. Sunucu iletişim portu oluştur */
    status = FltCreateCommunicationPort(
        (PFLT_FILTER)g_ChronosData.FilterHandle,
        &g_ChronosData.ServerPort,
        &oa,
        NULL,
        ChronosPortConnect,
        ChronosPortDisconnect,
        NULL,
        CHRONOS_MAX_CONNECTIONS
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        CHRONOS_LOG(DPFLTR_ERROR_LEVEL, "FltCreateCommunicationPort basarisiz: 0x%08X", status);
        goto cleanup;
    }

    /* 4. Filtrelemeyi başlat */
    status = FltStartFiltering((PFLT_FILTER)g_ChronosData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        CHRONOS_LOG(DPFLTR_ERROR_LEVEL, "FltStartFiltering basarisiz: 0x%08X", status);
        FltCloseCommunicationPort(g_ChronosData.ServerPort);
        goto cleanup;
    }

    CHRONOS_LOG(DPFLTR_TRACE_LEVEL, "Chronos MiniFilter aktif. Port: %S", CHRONOS_PORT_NAME);
    return STATUS_SUCCESS;

cleanup:
    if (g_ChronosData.FilterHandle) {
        FltUnregisterFilter((PFLT_FILTER)g_ChronosData.FilterHandle);
    }
    return status;
}
