    typedef struct _CLIENT_ID {
      HANDLE  UniqueProcess;
      HANDLE  UniqueThread;
    } CLIENT_ID, *PCLIENT_ID;
    typedef signed   __int64 QUAD ;
    
    typedef short CSHORT;
    typedef LONG NTSTATUS, *PNTSTATUS;
    typedef struct _UNICODE_STRING {
      USHORT Length;
      USHORT MaximumLength;
      PWSTR  Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;
    typedef const UNICODE_STRING* PCUNICODE_STRING;
    typedef struct _STRING {
      USHORT Length;
      USHORT MaximumLength;
      PCHAR  Buffer;
    } STRING, *PSTRING;
    typedef STRING ANSI_STRING;
    typedef PSTRING PANSI_STRING;
    typedef STRING OEM_STRING;
    typedef PSTRING POEM_STRING;
    typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
    typedef struct _OBJECT_ATTRIBUTES {
      ULONG Length;
      HANDLE RootDirectory;
      PUNICODE_STRING ObjectName;
      ULONG Attributes;                      
      PVOID SecurityDescriptor;              
      PVOID SecurityQualityOfService;
    } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

    typedef enum _OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation,
        ObjectNameInformation,
        ObjectTypeInformation,
        ObjectTypesInformation,
        ObjectHandleFlagInformation,
        ObjectSessionInformation,
        MaxObjectInfoClass
    } OBJECT_INFORMATION_CLASS;

    typedef enum _EVENT_TYPE {
        NotificationEvent,
        SynchronizationEvent
    } EVENT_TYPE, *PEVENT_TYPE;

    typedef enum _KPROFILE_SOURCE
    {
        ProfileTime,
        ProfileAlignmentFixup,
        ProfileTotalIssues,
        ProfilePipelineDry,
        ProfileLoadInstructions,
        ProfilePipelineFrozen,
        ProfileBranchInstructions,
        ProfileTotalNonissues,
        ProfileDcacheMisses,
        ProfileIcacheMisses,
        ProfileCacheMisses,
        ProfileBranchMispredictions,
        ProfileStoreInstructions,
        ProfileFpInstructions,
        ProfileIntegerInstructions,
        Profile2Issue,
        Profile3Issue,
        Profile4Issue,
        ProfileSpecialInstructions,
        ProfileTotalCycles,
        ProfileIcacheIssues,
        ProfileDcacheAccesses,
        ProfileMemoryBarrierCycles,
        ProfileLoadLinkedIssues,
        ProfileMaximum
    } KPROFILE_SOURCE;

    typedef enum _IO_COMPLETION_INFORMATION_CLASS
    {
        IoCompletionBasicInformation
    } IO_COMPLETION_INFORMATION_CLASS;

    typedef struct _IO_STATUS_BLOCK
    {
        union
        {
            NTSTATUS Status;
            PVOID Pointer;
        };
        ULONG_PTR Information;
    } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

    typedef struct _PORT_MESSAGE
    {
        union
        {
            struct
            {
                CSHORT DataLength;
                CSHORT TotalLength;
            } s1;
            ULONG Length;
        } u1;
        union
        {
            struct
            {
                CSHORT Type;
                CSHORT DataInfoOffset;
            } s2;
            ULONG ZeroInit;
        } u2;
        union
        {
            CLIENT_ID ClientId;
            QUAD DoNotUseThisField;
        };
        ULONG MessageId;
        union
        {
            SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
            ULONG CallbackId; // only valid for LPC_REQUEST messages
        };
    } PORT_MESSAGE, *PPORT_MESSAGE;

    typedef enum _THREADINFOCLASS {
      ThreadBasicInformation,
      ThreadTimes,
      ThreadPriority,
      ThreadBasePriority,
      ThreadAffinityMask,
      ThreadImpersonationToken,
      ThreadDescriptorTableEntry,
      ThreadEnableAlignmentFaultFixup,
      ThreadEventPair_Reusable,
      ThreadQuerySetWin32StartAddress,
      ThreadZeroTlsCell,
      ThreadPerformanceCount,
      ThreadAmILastThread,
      ThreadIdealProcessor,
      ThreadPriorityBoost,
      ThreadSetTlsArrayAddress,
      ThreadIsIoPending,
      ThreadHideFromDebugger,
      ThreadBreakOnTermination,
      MaxThreadInfoClass
    } THREADINFOCLASS;
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemInformationClassMin = 0,
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemNotImplemented1 = 4,
    SystemProcessInformation = 5,
    SystemProcessesAndThreadsInformation = 5,
    SystemCallCountInfoInformation = 6,
    SystemCallCounts = 6,
    SystemDeviceInformation = 7,
    SystemConfigurationInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemProcessorTimes = 8,
    SystemFlagsInformation = 9,
    SystemGlobalFlag = 9,
    SystemCallTimeInformation = 10,
    SystemNotImplemented2 = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemLockInformation = 12,
    SystemStackTraceInformation = 13,
    SystemNotImplemented3 = 13,
    SystemPagedPoolInformation = 14,
    SystemNotImplemented4 = 14,
    SystemNonPagedPoolInformation = 15,
    SystemNotImplemented5 = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemPagefileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemInstructionEmulationCounts = 19,
    SystemVdmBopInformation = 20,
    SystemInvalidInfoClass1 = 20,   
    SystemFileCacheInformation = 21,
    SystemCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemProcessorStatistics = 23,
    SystemDpcBehaviourInformation = 24,
    SystemDpcInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemNotImplemented6 = 25,
    SystemLoadImage = 26,
    SystemUnloadImage = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemTimeAdjustment = 28,
    SystemSummaryMemoryInformation = 29,
    SystemNotImplemented7 = 29,
    SystemNextEventIdInformation = 30,
    SystemNotImplemented8 = 30,
    SystemEventIdsInformation = 31,
    SystemNotImplemented9 = 31,
    SystemCrashDumpInformation = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemLoadAndCallImage = 38,
    SystemPrioritySeparation = 39,
    SystemPlugPlayBusInformation = 40,
    SystemNotImplemented10 = 40,
    SystemDockInformation = 41,
    SystemNotImplemented11 = 41,
    /* SystemPowerInformation = 42, Conflicts with POWER_INFORMATION_LEVEL 1 */
    SystemInvalidInfoClass2 = 42,
    SystemProcessorSpeedInformation = 43,
    SystemInvalidInfoClass3 = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemSetTimeSlipEvent = 46,
    SystemCreateSession = 47,
    SystemDeleteSession = 48,
    SystemInvalidInfoClass4 = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemAddVerifier = 52,
    SystemSessionProcessesInformation   = 53,
    SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS {
  FileDirectoryInformation = 1,
  FileFullDirectoryInformation,
  FileBothDirectoryInformation,
  FileBasicInformation,
  FileStandardInformation,
  FileInternalInformation,
  FileEaInformation,
  FileAccessInformation,
  FileNameInformation,
  FileRenameInformation,
  FileLinkInformation,
  FileNamesInformation,
  FileDispositionInformation,
  FilePositionInformation,
  FileFullEaInformation,
  FileModeInformation,
  FileAlignmentInformation,
  FileAllInformation,
  FileAllocationInformation,
  FileEndOfFileInformation,
  FileAlternateNameInformation,
  FileStreamInformation,
  FilePipeInformation,
  FilePipeLocalInformation,
  FilePipeRemoteInformation,
  FileMailslotQueryInformation,
  FileMailslotSetInformation,
  FileCompressionInformation,
  FileObjectIdInformation,
  FileCompletionInformation,
  FileMoveClusterInformation,
  FileQuotaInformation,
  FileReparsePointInformation,
  FileNetworkOpenInformation,
  FileAttributeTagInformation,
  FileTrackingInformation,
  FileIdBothDirectoryInformation,
  FileIdFullDirectoryInformation,
  FileValidDataLengthInformation,
  FileShortNameInformation,
  FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
  LARGE_INTEGER  CreationTime;
  LARGE_INTEGER  LastAccessTime;
  LARGE_INTEGER  LastWriteTime;
  LARGE_INTEGER  ChangeTime;
  ULONG  FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS {
MemoryBasicInformation,
MemoryWorkingSetList,
MemorySectionName,
MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
  KeyValueBasicInformation,
  KeyValueFullInformation,
  KeyValuePartialInformation,
  KeyValueFullInformationAlign64,
  KeyValuePartialInformationAlign64
} KEY_VALUE_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS {
    AtomBasicInformation,
    AtomListInformation
} ATOM_INFORMATION_CLASS;

typedef USHORT RTL_ATOM, *PRTL_ATOM;
typedef ULONG WAIT_TYPE;

typedef enum _WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout,
    WorkerFactoryRetryTimeout,
    WorkerFactoryIdleTimeout,
    WorkerFactoryBindingCount,
    WorkerFactoryThreadMinimum,
    WorkerFactoryThreadMaximum,
    WorkerFactoryPaused,
    WorkerFactoryBasicInformation, // name:wow64:whNtQueryInformationWorkerFactory_WorkerFactoryBasicInformation
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation, // name:wow64:whNtQueryInformationWorkerFactory_WorkerFactoryStackInformation
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

typedef enum _KEY_SET_INFORMATION_CLASS {
  KeyLastWriteTimeInformation
} KEY_SET_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE
{
    ULONG Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR SpareBits1 : 6;
                    UCHAR IFEOKeyState : 2; // PS_IFEO_KEY_STATE
                    UCHAR SpareBits2 : 6;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO; 

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
    AlpcBasicInformation, // q: out ALPC_BASIC_INFORMATION
    AlpcPortInformation, // s: in ALPC_PORT_ATTRIBUTES
    AlpcAssociateCompletionPortInformation, // s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT
    AlpcConnectedSIDInformation, // q: in SID
    AlpcServerInformation, // q: inout ALPC_SERVER_INFORMATION
    AlpcMessageZoneInformation, // s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION
    AlpcRegisterCompletionListInformation, // s: in ALPC_PORT_COMPLETION_LIST_INFORMATION
    AlpcUnregisterCompletionListInformation, // s: VOID
    AlpcAdjustCompletionListConcurrencyCountInformation, // s: in ULONG
    AlpcRegisterCallback, // kernel-mode only // rev
    AlpcDisableCompletionList, // s: VOID // rev
    MaxAlpcPortInfoClass
} ALPC_PORT_INFORMATION_CLASS;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
    PVOID KeyContext;
    PVOID ApcContext;
    IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID ALPC_HANDLE, *PALPC_HANDLE;

typedef struct _ALPC_DATA_VIEW_ATTR
{
    ULONG Flags;
    ALPC_HANDLE SectionHandle;
    PVOID ViewBase; // must be zero on input
    SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, *PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: HANDLE
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // 10
    ProcessLdtSize,
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only)
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,
    ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
    ProcessAffinityMask, // s: KAFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // 30, q: HANDLE
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: ULONG
    ProcessExecuteFlags, // qs: ULONG
    ProcessResourceManagement,
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
    ProcessPagePriority, // q: ULONG
    ProcessInstrumentationCallback, // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // q: ULONG_PTR
    ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode,
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _SECTION_INFORMATION_CLASS
{
    SectionBasicInformation,
    SectionImageInformation,
    SectionRelocationInformation, // name:wow64:whNtQuerySection_SectionRelocationInformation
    MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef enum _VDMSERVICECLASS
{
    VdmStartExecution,
    VdmQueueInterrupt,
    VdmDelayInterrupt,
    VdmInitialize,
    VdmFeatures,
    VdmSetInt21Handler,
    VdmQueryDir,
    VdmPrinterDirectIoOpen,
    VdmPrinterDirectIoClose,
    VdmPrinterInitialize,
    VdmSetLdtEntries,
    VdmSetProcessLdtInfo,
    VdmAdlibEmulation,
    VdmPMCliControl,
    VdmQueryVdmProcess
} VDMSERVICECLASS, *PVDMSERVICECLASS;

typedef struct _PORT_VIEW
{
    ULONG Length;
    HANDLE SectionHandle;
    ULONG SectionOffset;
    SIZE_T ViewSize;
    PVOID ViewBase;
    PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW
{
    ULONG Length;
    SIZE_T ViewSize;
    PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

typedef enum _MUTANT_INFORMATION_CLASS
{
    MutantBasicInformation,
    MutantOwnerInformation
} MUTANT_INFORMATION_CLASS;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
    AlpcMessageSidInformation, // q: out SID
    AlpcMessageTokenModifiedIdInformation,  // q: out LUID
    MaxAlpcMessageInfoClass
} ALPC_MESSAGE_INFORMATION_CLASS, *PALPC_MESSAGE_INFORMATION_CLASS;

typedef struct _INITIAL_TEB
{
    struct
    {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _M_X64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
    TimerSetCoalescableTimer,
    MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
    PVOID PortContext;
    PVOID MessageContext;
    ULONG Sequence;
    ULONG MessageId;
    ULONG CallbackId;
} ALPC_CONTEXT_ATTR, *PALPC_CONTEXT_ATTR;

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
    HardwareProfileChangeEvent,
    TargetDeviceChangeEvent,
    DeviceClassChangeEvent,
    CustomDeviceEvent,
    DeviceInstallEvent,
    DeviceArrivalEvent,
    PowerEvent,
    VetoEvent,
    BlockedDriverEvent,
    InvalidIDEvent,
    MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, *PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE
{
         PNP_VetoTypeUnknown = 0,
         PNP_VetoLegacyDevice = 1,
         PNP_VetoPendingClose = 2,
         PNP_VetoWindowsApp = 3,
         PNP_VetoWindowsService = 4,
         PNP_VetoOutstandingOpen = 5,
         PNP_VetoDevice = 6,
         PNP_VetoDriver = 7,
         PNP_VetoIllegalDeviceRequest = 8,
         PNP_VetoInsufficientPower = 9,
         PNP_VetoNonDisableable = 10,
         PNP_VetoLegacyDriver = 11,
         PNP_VetoInsufficientRights = 12
} PNP_VETO_TYPE;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
    GUID EventGuid;
    PLUGPLAY_EVENT_CATEGORY EventCategory;
    PULONG Result;
    ULONG Flags;
    ULONG TotalSize;
    PVOID DeviceObject;

    union
    {
        struct
        {
            GUID ClassGuid;
            WCHAR SymbolicLinkName[1];
        } DeviceClass;
        struct
        {
            WCHAR DeviceIds[1];
        } TargetDevice;
        struct
        {
            WCHAR DeviceId[1];
        } InstallDevice;
        struct
        {
            PVOID NotificationStructure;
            WCHAR DeviceIds[1];
        } CustomNotification;
        struct
        {
            PVOID Notification;
        } ProfileNotification;
        struct
        {
            ULONG NotificationCode;
            ULONG NotificationData;
        } PowerNotification;
        struct
        {
            PNP_VETO_TYPE VetoType;
            WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<null>VetoName<null><null>
        } VetoNotification;
        struct
        {
            GUID BlockedDriverGuid;
        } BlockedDriverNotification;
        struct
        {
            WCHAR ParentId[1];
        } InvalidIDNotification;
    } u;
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef enum _EVENT_INFORMATION_CLASS
{
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _PORT_INFORMATION_CLASS
{
    PortBasicInformation,
    PortDumpInformation
} PORT_INFORMATION_CLASS;

typedef enum _TIMER_INFORMATION_CLASS
{
    TimerBasicInformation
} TIMER_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsSectorSizeInformation, // since WIN8
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef enum _SYSDBG_COMMAND
{
    SysDbgQueryModuleInformation,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall,
    SysDbgClearSpecialCalls,
    SysDbgQuerySpecialCalls,
    SysDbgBreakPoint,
    SysDbgQueryVersion,
    SysDbgReadVirtual,
    SysDbgWriteVirtual,
    SysDbgReadPhysical,
    SysDbgWritePhysical,
    SysDbgReadControlSpace,
    SysDbgWriteControlSpace,
    SysDbgReadIoSpace,
    SysDbgWriteIoSpace,
    SysDbgReadMsr,
    SysDbgWriteMsr,
    SysDbgReadBusData,
    SysDbgWriteBusData,
    SysDbgCheckLowMemory,
    SysDbgEnableKernelDebugger,
    SysDbgDisableKernelDebugger,
    SysDbgGetAutoKdEnable,
    SysDbgSetAutoKdEnable,
    SysDbgGetPrintBufferSize,
    SysDbgSetPrintBufferSize,
    SysDbgGetKdUmExceptionEnable,
    SysDbgSetKdUmExceptionEnable,
    SysDbgGetTriageDump,
    SysDbgGetKdBlockEnable,
    SysDbgSetKdBlockEnable,
    SysDbgRegisterForUmBreakInfo,
    SysDbgGetUmBreakPid,
    SysDbgClearUmBreakPid,
    SysDbgGetUmAttachPid,
    SysDbgClearUmAttachPid
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef enum _DEBUGOBJECTINFOCLASS
{
    DebugObjectFlags = 1,
    MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
    MemoryReserveUserApc,
    MemoryReserveIoCompletion,
    MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE;

typedef struct _KEY_VALUE_ENTRY
{
    PUNICODE_STRING ValueName;
    ULONG DataLength;
    ULONG DataOffset;
    ULONG Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
    PlugPlayControlEnumerateDevice,
    PlugPlayControlRegisterNewDevice,
    PlugPlayControlDeregisterDevice,
    PlugPlayControlInitializeDevice,
    PlugPlayControlStartDevice,
    PlugPlayControlUnlockDevice,
    PlugPlayControlQueryAndRemoveDevice,
    PlugPlayControlUserResponse,
    PlugPlayControlGenerateLegacyDevice,
    PlugPlayControlGetInterfaceDeviceList,
    PlugPlayControlProperty,
    PlugPlayControlDeviceClassAssociation,
    PlugPlayControlGetRelatedDevice,
    PlugPlayControlGetInterfaceDeviceAlias,
    PlugPlayControlDeviceStatus,
    PlugPlayControlGetDeviceDepth,
    PlugPlayControlQueryDeviceRelations,
    PlugPlayControlTargetDeviceRelation,
    PlugPlayControlQueryConflictList,
    PlugPlayControlRetrieveDock,
    PlugPlayControlResetDevice,
    PlugPlayControlHaltDevice,
    PlugPlayControlGetBlockedDriverList,
    MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, *PPLUGPLAY_CONTROL_CLASS;

typedef enum _TIMER_TYPE {
  NotificationTimer,
  SynchronizationTimer
} TIMER_TYPE;

typedef struct _ALPC_SECURITY_ATTR
{
    ULONG Flags;
    PSECURITY_QUALITY_OF_SERVICE SecurityQos;
    ALPC_HANDLE ContextHandle; // dbg
    ULONG Reserved1;
    ULONG Reserved2;
} ALPC_SECURITY_ATTR, *PALPC_SECURITY_ATTR;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

/*typedef struct __WSABUF {
  u_long   len;
  char FAR *buf;
} WSABUF, *LPWSABUF;*/

// Fluffy definition
 
typedef struct _AFD_WSABUF {
     UINT  len;
     PCHAR buf;
} AFD_WSABUF, *PAFD_WSABUF;
 
typedef struct  _AFD_RECV_INFO {
     PAFD_WSABUF                 BufferArray;
     ULONG                       BufferCount;
     ULONG                       AfdFlags;
     ULONG                       TdiFlags;
} AFD_RECV_INFO , *PAFD_RECV_INFO ;
 
typedef struct _AFD_RECV_INFO_UDP {
     PAFD_WSABUF                 BufferArray;
     ULONG                       BufferCount;
     ULONG                       AfdFlags;
     ULONG                       TdiFlags;
     PVOID                       Address;
     INT                         AddressLength;
} AFD_RECV_INFO_UDP, *PAFD_RECV_INFO_UDP;
 
typedef struct  _AFD_SEND_INFO {
     PAFD_WSABUF                 BufferArray;
     ULONG                       BufferCount;
     ULONG                       AfdFlags;
     ULONG                       TdiFlags;
} AFD_SEND_INFO , *PAFD_SEND_INFO ;
 
typedef struct _AFD_SEND_INFO_UDP {
     PAFD_WSABUF                 BufferArray;
     ULONG                       BufferCount;
     ULONG                       AfdFlags;
     ULONG                       Padding[9];
     ULONG                       SizeOfRemoteAddress;
     PVOID                       RemoteAddress;
} AFD_SEND_INFO_UDP, *PAFD_SEND_INFO_UDP;

typedef struct _AFD_CONNECT_INFO {
    BOOLEAN             UseSAN;
    ULONG               Root;
    PVOID               ConnectionEndpoint;
#if 1 /* bruening: based on win7 observation: i#376 */
    SOCKADDR                        RemoteAddress;
#else
    TRANSPORT_ADDRESS           RemoteAddress;
#endif
} AFD_CONNECT_INFO , *PAFD_CONNECT_INFO ;