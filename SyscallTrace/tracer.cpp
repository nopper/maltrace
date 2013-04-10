#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pin.h"

void Log(const char *fmt, ...);

// all our windows stuff.. needs its own namespace..
namespace W {
    
    #include <WinSock2.h>
    #include <windows.h>
    #include "definitions.h"

    #define LOGFN Log

    #define INLINEDUMP(x, fmt) void dump_##x(x value, const char *varname) { LOGFN("\t%s %s = " fmt "\n", #x, varname, value); }
    #define INLINEDUMPAT(x, fmt) void dump_##x##_at(x value, unsigned int idx, const char *varname) { LOGFN("\t%s %s[%d] = " fmt "\n", #x, varname, idx, value); }
    #define INLINEDDUMP(x, fmt) void dump_##x(x value, const char *varname) { LOGFN("\t%s %s = " fmt "\n", #x, varname, *value); }
    #define INLINEDUMPEX(x, fmt, exp) void dump_##x(x value, const char *varname) { LOGFN("\t%s %s = " fmt "\n", #x, varname, exp); }

    INLINEDUMP(HANDLE, "0x%p");
    INLINEDUMPAT(HANDLE, "0x%p")

    INLINEDUMP(SIZE_T, "0x%p")
    INLINEDDUMP(PSIZE_T, "0x%p");
    INLINEDUMP(KAFFINITY, "0x%p");
    INLINEDUMP(PVOID, "0x%p");
    INLINEDUMP(PSID, "0x%p");

    INLINEDUMP(ULONG, "%Lu");
    INLINEDUMP(LONG, "%L");
    INLINEDDUMP(PULONG, "%Lu");
    INLINEDUMP(ULONG_PTR, "%Lu");

    INLINEDUMP(DWORD, "%Lu");
    INLINEDUMP(USHORT, "%d");
    INLINEDUMP(WORD, "%d"); // unsigned short
    INLINEDUMP(ACCESS_MASK, "%d");
    INLINEDUMP(UCHAR, "%u");
    INLINEDDUMP(PRTL_ATOM, "%d"); // unsigned short*
    INLINEDUMP(ATOM, "%d");
    INLINEDUMP(NTSTATUS, "0x%p");

    INLINEDUMP(PUNICODE_STRING, "\"\"\"%wZ\"\"\"");
    INLINEDUMP(PWSTR, "\"\"\"%ws\"\"\"");

    typedef unsigned int ENUM;

    INLINEDUMP(ENUM, "%u");

    INLINEDUMPEX(BOOLEAN, "%s", value == TRUE ? "TRUE" : "FALSE");

    INLINEDUMPEX(PLARGE_INTEGER, "%llu", (unsigned long long)value->QuadPart);
    INLINEDUMPEX(LARGE_INTEGER, "%llu", (unsigned long long)value.QuadPart);
    INLINEDUMPEX(LUID, "%lu %lu", (value.HighPart, value.LowPart));

    #define DUMPFUNC(x) void dump_##x(x value, const char* varname)

    void dump_contents(const char* buff, ULONG len, const char* varname)
    {
        Log("\tHEXDUMP %s = \"\"\"", varname, len);
        for (int i = 0; i < len; i++)
            Log("%02X", (unsigned char)buff[i]);
        Log("\"\"\"\n");
    }

    DUMPFUNC(PPORT_MESSAGE)
    {
        LOGFN("\tPPORT_MESSAGE %s = {\n", varname);
        LOGFN("\t"); dump_USHORT(value->u1.s1.DataLength, "u1.s1.DataLength");
        LOGFN("\t"); dump_USHORT(value->u1.s1.TotalLength, "u1.s1.TotalLength");
        LOGFN("\t"); dump_ULONG(value->u1.Length, "u1.Length");

        LOGFN("\t"); dump_USHORT(value->u2.s2.Type, "u2.s2.Type");
        LOGFN("\t"); dump_USHORT(value->u2.s2.DataInfoOffset, "u2.s2.DataInfoOffset");
        LOGFN("\t"); dump_ULONG(value->u2.ZeroInit, "u1.ZeroInit");

        LOGFN("\t"); dump_HANDLE(value->ClientId.UniqueProcess, "ClientId.UniqueProcess");
        LOGFN("\t"); dump_HANDLE(value->ClientId.UniqueThread, "ClientId.UniqueThread");

        LOGFN("\t"); dump_ULONG(value->MessageId, "MessageId");
        LOGFN("\t"); dump_ULONG_PTR(value->ClientViewSize, "ClientViewSize");
        LOGFN("\t"); dump_ULONG(value->CallbackId, "CallbackId");

        const char* buff = (const char *)value;
        buff += sizeof(PORT_MESSAGE);

        LOGFN("\t"); dump_contents((const char *)buff, value->u1.s1.DataLength, "Message");
        LOGFN("\t}\n");
    }

    DUMPFUNC(PGENERIC_MAPPING)
    {
        LOGFN("\tPGENERIC_MAPPING %s = {\n", varname);
        LOGFN("\t"); dump_ULONG(value->GenericRead, "GenericRead");
        LOGFN("\t"); dump_ULONG(value->GenericWrite, "GenericWrite");
        LOGFN("\t"); dump_ULONG(value->GenericExecute, "GenericExecute");
        LOGFN("\t"); dump_ULONG(value->GenericAll, "GenericAll");
        LOGFN("\t}\n");
    }

    DUMPFUNC(PPRIVILEGE_SET)
    {
        LOGFN("\tPPRIVILEGE_SET %s = {\n", varname);
        LOGFN("\t"); dump_ULONG(value->PrivilegeCount, "PrivilegeCount");
        LOGFN("\t"); dump_ULONG(value->Control, "Control");
        /*for (int i = 0; i < value->PrivilegeCount; i++)
        {
            LOGFN("\t"); dump_LUID(value->Privilege[i].Luid, "Luid");
            LOGFN("\t"); dump_DWORD(value->Privilege[i].Attributes, "Attributes");
        }*/
        LOGFN("\t}\n");
    }

    DUMPFUNC(PISECURITY_DESCRIPTOR)
    {
        LOGFN("\tPSECURITY_DESCRIPTOR %s = {\n", varname);
        LOGFN("\t"); dump_UCHAR(value->Revision, "Revision");
        LOGFN("\t"); dump_UCHAR(value->Sbz1, "Sbz1");
        LOGFN("\t"); dump_WORD(value->Control, "Control");
        LOGFN("\t"); dump_PVOID(value->Owner, "Owner");
        LOGFN("\t"); dump_PVOID(value->Group, "Group");

        #if 0
        if (!value->Sacl)
            LOGFN("\tSacl = NULL\n");
        else
        {
            LOGFN("\tSacl = {\n");
            LOGFN("\t\t"); dump_UCHAR(value->Sacl->AclRevision, "AclRevision");
            LOGFN("\t\t"); dump_UCHAR(value->Sacl->Sbz1, "Sbz1");
            LOGFN("\t\t"); dump_WORD(value->Sacl->AclSize, "AclSize");
            LOGFN("\t\t"); dump_WORD(value->Sacl->AceCount, "AceCount");
            LOGFN("\t\t"); dump_UCHAR(value->Sacl->Sbz2, "Sbz2");
            LOGFN("\t\t}");
        }

        if (!value->Dacl)
            LOGFN("\tDacl = NULL\n");
        else
        {
            LOGFN("\tDacl = {\n");
            LOGFN("\t\t"); dump_UCHAR(value->Dacl->AclRevision, "AclRevision");
            LOGFN("\t\t"); dump_UCHAR(value->Dacl->Sbz1, "Sbz1");
            LOGFN("\t\t"); dump_WORD(value->Dacl->AclSize, "AclSize");
            LOGFN("\t\t"); dump_WORD(value->Dacl->AceCount, "AceCount");
            LOGFN("\t\t"); dump_UCHAR(value->Dacl->Sbz2, "Sbz2");
            LOGFN("\t\t}");
        }
        #else
        LOGFN("\t"); dump_PVOID(value->Sacl, "Sacl");
        LOGFN("\t"); dump_PVOID(value->Dacl, "Dacl");
        #endif

        LOGFN("\t}\n");
    }

    DUMPFUNC(PGROUP_AFFINITY)
    {
        LOGFN("\tPGROUP_AFFINITY %s = {\n", varname);
        LOGFN("\t"); dump_KAFFINITY(value->Mask, "Mask");
        LOGFN("\t"); dump_WORD(value->Group, "Group");
        LOGFN("\t"); dump_WORD(value->Reserved[0], "Reserved0");
        LOGFN("\t"); dump_WORD(value->Reserved[1], "Reserved1");
        LOGFN("\t"); dump_WORD(value->Reserved[2], "Reserved2");
        LOGFN("\t}\n");
    }

    DUMPFUNC(PCLIENT_ID)
    {
        LOGFN("\tPCLIENT_ID %s = {\n", varname);
        LOGFN("\t"); dump_PVOID(value->UniqueProcess, "UniqueProcess");
        LOGFN("\t"); dump_PVOID(value->UniqueThread, "UniqueThread");
        LOGFN("\t}\n");
    }

    DUMPFUNC(PTOKEN_PRIVILEGES)
    {
        LOGFN("\tPTOKEN_PRIVILEGES %s = {\n", varname);
        LOGFN("\t"); dump_DWORD(value->PrivilegeCount, "PrivilegeCount");
        /*for (int i = 0; i < value->PrivilegeCount; i++)
        {
            LOGFN("\t"); dump_LUID(value->Privileges[i].Luid, "Luid");
            LOGFN("\t"); dump_DWORD(value->Privileges[i].Attributes, "Attributes");
        }*/
        LOGFN("\t}\n");
    }

    DUMPFUNC(PFILE_BASIC_INFORMATION)
    {
        // TODO: may be a string formatting
        LOGFN("\tPFILE_BASIC_INFORMATION %s = {\n", varname);
        LOGFN("\t\tCreationTime: %llu\n"
              "\t\tLastAccessTime: %llu\n"
              "\t\tLastWriteTime: %llu\n"
              "\t\tChangeTime: %llu\n\t}\n",
              (unsigned long long)value->CreationTime.QuadPart,
              (unsigned long long)value->LastAccessTime.QuadPart,
              (unsigned long long)value->LastWriteTime.QuadPart,
              (unsigned long long)value->ChangeTime.QuadPart);
    }

    DUMPFUNC(LPGUID)
    {
        LOGFN("\tLPGUID %s = {%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X}\n",
            varname,
            value->Data1,
            value->Data2,
            value->Data3,
            value->Data4[0],
            value->Data4[1],
            value->Data4[2],
            value->Data4[3],
            value->Data4[4],
            value->Data4[5],
            value->Data4[6],
            value->Data4[7]);
    }

    DUMPFUNC(PIO_STATUS_BLOCK)
    {
        LOGFN("\tPIO_STATUS_BLOCK %s = {\n", varname);
        LOGFN("\t"); dump_PVOID(value->Pointer, "Pointer");
        LOGFN("\t"); dump_ULONG(value->Information, "Status");
        LOGFN("\t"); dump_ULONG(value->Information, "Information");
        LOGFN("\t}\n");
    }

    DUMPFUNC(POBJECT_ATTRIBUTES)
    {
        LOGFN("\tOBJECT_ATTRIBUTES %s = {\n", varname);
        LOGFN("\t"); dump_ULONG(value->Length, "Length");
        LOGFN("\t"); dump_HANDLE(value->RootDirectory, "RootDirectory");
        LOGFN("\t"); dump_PUNICODE_STRING(value->ObjectName, "ObjectName");
        LOGFN("\t"); dump_ULONG(value->Attributes, "Attributes");
        LOGFN("\t"); dump_PVOID(value->SecurityDescriptor, "SecurityDescriptor");
        LOGFN("\t"); dump_PVOID(value->SecurityQualityOfService, "SecurityQualityOfService");
        LOGFN("\t}\n");
    }

}

#define MAX_SYSCALL (64 * 1024)

UINT32 g_imgid = 0;
ADDRINT g_lowaddr, g_highaddr, g_entryPoint = 0;
BOOL g_passedEntryPoint = FALSE;
uint32_t g_lastcaller;

static const char *g_syscall_names[MAX_SYSCALL];
static unsigned short g_syscall_nargs[MAX_SYSCALL];

unsigned long syscall_name_to_number(const char *name)
{
    for (unsigned long i = 0; i < MAX_SYSCALL; i++) {
        if(g_syscall_names[i] != NULL &&
                !strcmp(g_syscall_names[i] + 2, name + 2)) {
            return i;
        }
    }
    //printf("System Call %s not found!\n", name);
    return 0;
}

// stole this lovely source code from the rreat library.
static void enum_syscalls()
{
    // no boundary checking at all, I assume ntdll is not malicious..
    // besides that, we are in our own process, _should_ be fine..
    unsigned char *image = (unsigned char *) W::GetModuleHandle("ntdll");
    W::IMAGE_DOS_HEADER *dos_header = (W::IMAGE_DOS_HEADER *) image;
    W::IMAGE_NT_HEADERS *nt_headers = (W::IMAGE_NT_HEADERS *)(image +
        dos_header->e_lfanew);
    W::IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    W::IMAGE_EXPORT_DIRECTORY *export_directory =
        (W::IMAGE_EXPORT_DIRECTORY *)(image + data_directory->VirtualAddress);
    unsigned long *address_of_names = (unsigned long *)(image +
        export_directory->AddressOfNames);
    unsigned long *address_of_functions = (unsigned long *)(image +
        export_directory->AddressOfFunctions);
    unsigned short *address_of_name_ordinals = (unsigned short *)(image +
        export_directory->AddressOfNameOrdinals);
    unsigned long number_of_names = MIN(export_directory->NumberOfFunctions,
        export_directory->NumberOfNames);
    for (unsigned long i = 0; i < number_of_names; i++) {
        const char *name = (const char *)(image + address_of_names[i]);
        unsigned char *addr = image + address_of_functions[
            address_of_name_ordinals[i]];
        if(!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
            // does the signature match?
            // either:   mov eax, syscall_number ; mov ecx, some_value
            // or:       mov eax, syscall_number ; xor ecx, ecx
            // or:       mov eax, syscall_number ; mov edx, 0x7ffe0300
            if(*addr == 0xb8 &&
                    (addr[5] == 0xb9 || addr[5] == 0x33 || addr[5] == 0xba)) {
                unsigned long syscall_number = *(unsigned long *)(addr + 1);
                if(syscall_number < MAX_SYSCALL) {
                    //printf("Sycall %d => %s\n", syscall_number, name);
                    g_syscall_names[syscall_number] = name;
                }
            }
        }
    }
}

typedef struct _syscall_t {
    ADDRINT syscall_number;
} syscall_t;

int g_process_handle_count = 0;
W::HANDLE g_process_handle[256] = {0};

int g_thread_handle_count = 0;
W::HANDLE g_thread_handle[256] = {0};
PIN_LOCK g_write_lock;
FILE *g_file;


/* This function assumes that you already owns the file lock. */
void Log(const char *fmt, ...)
{
    va_list arglist;
    va_start(arglist, fmt);
    vfprintf(g_file, fmt, arglist);
    va_end(arglist);
    fflush(g_file);
}

// extract arguments to a system call in a syscall_entry_callback
void syscall_get_arguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...)
{
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        int index = va_arg(args, int);
        ADDRINT *ptr = va_arg(args, ADDRINT *);
        *ptr = PIN_GetSyscallArgument(ctx, std, index);
    }
    va_end(args);
}

uint32_t FindCaller(uint32_t ebp)
{
    uint32_t eip;
    uint32_t found = 0;
    uint32_t count = 0;
    while(ebp != 0 && count < 40)
    {
        if(PIN_SafeCopy(&eip, (uint32_t *)(ebp + 4), 4) != 4) 
            break;

        if (IMG_Id(IMG_FindByAddress((ADDRINT)(void *)eip)) == g_imgid)
            if (!found)
                PIN_SafeCopy(&found, (uint32_t *)(ebp + 4), 4);

        //fprintf(stdout, "CALLER: %p\n", eip);

        if(PIN_SafeCopy(&ebp, (uint32_t *)ebp, 4) != 4) 
            break;

        count++;
    }

    if (found != 0 && found != g_lastcaller)
    {
        /*char buff[12];
        PIN_SafeCopy(&buff, (uint32_t *)(found - 12), 12);
        for (int i = 0; i < 12; i++)
            printf("%02X", (unsigned char)buff[i]);
        printf(" [count %d]\n", count);*/

        g_lastcaller = found;
        return found;
    }

    return 0;
}

#include "generated.c"

void syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std,
    void *v)
{
/*    syscall_t *sc = &((syscall_t *) v)[thread_id];
    unsigned long syscall_number = sc->syscall_number;

    if(g_passedEntryPoint && syscall_number < MAX_SYSCALL && g_syscall_names[syscall_number]) {
        GetLock(&g_write_lock, thread_id + 1);
        Log("[thread id %d] SYSCALL %ld (%s): returns: 0x%lx\n",
            thread_id, syscall_number, g_syscall_names[syscall_number], 
            (unsigned long)PIN_GetSyscallReturn(ctx, std));
        ReleaseLock(&g_write_lock);
    }*/
}

VOID Instruction(INS ins, VOID *v)
{
    if (!g_passedEntryPoint && INS_Address(ins) == g_entryPoint)
        g_passedEntryPoint = true;
}

VOID ImageLoad(IMG img, VOID *v)
{
    if (IMG_IsMainExecutable(img))
    {
        //fprintf(stdout, "%s: mapped at 0x%p - 0x%p ID %d\n", IMG_Name(img).c_str(), low, high, id);
        g_imgid = IMG_Id(img);
        g_lowaddr = IMG_LowAddress(img);
        g_highaddr = IMG_HighAddress(img);
        g_entryPoint = IMG_Entry(img);
    }
}

// Pin calls this function every time a new img is unloaded
// You can't instrument an image that is about to be unloaded
VOID ImageUnload(IMG img, VOID *v)
{
    //Log("# Unloading %s\n", IMG_Name(img).c_str());
}

KNOB<string> OutputLogFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "syscall.log", "specify output log file name");

int main(int argc, char *argv[])
{
    // Initialize symbol processing
    PIN_InitSymbols();

    if(PIN_Init(argc, argv)) {
        cerr << "This tool trace all the syscall invocations" << endl;
        cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
        return -1;
    }

    g_file = fopen(OutputLogFile.Value().c_str(), "wb");

    InitLock(&g_write_lock);

    enum_syscalls();
    init_common_syscalls();

    IMG_AddInstrumentFunction(ImageLoad, 0);
    IMG_AddUnloadFunction(ImageUnload, 0);
    INS_AddInstrumentFunction(Instruction, 0);

    static syscall_t sc[256] = {0};
    PIN_AddSyscallEntryFunction(&syscall_entry, &sc);
    PIN_AddSyscallExitFunction(&syscall_exit, &sc);

    PIN_StartProgram();
    return 0;
}
