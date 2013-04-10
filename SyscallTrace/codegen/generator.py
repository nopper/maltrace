import os
import re
import sys
import glob

from collections import defaultdict
from ConfigParser import ConfigParser

MOD_OPTIONAL = 1
MOD_INPUT    = 2
MOD_OUTPUT   = 4

def hookpresent(func):
    def wrapper(*args,**kwargs):
        self = args[0]
        parser = self.hooks.get(args[1][2:], None)

        type = func.__name__.split('_')[1]

        if parser is None or not parser.has_section(type):
            return False

        args = list(args)
        args.append(parser)
        return func(*tuple(args))
    return wrapper

class SyscallParser(object):
    def __init__(self):
        self.regex = re.compile(r'NTSYSCALLAPI\WNTSTATUS\WNTAPI\W([a-zA-Z]+)\(([^;]*);')
        self.regex_par = re.compile(r'\([^\)]+\)')
        self.syscalls = {}
        self.sys_supported = set()

        with open('syscalls.h') as f:
            for line in f:
                self.sys_supported.add(line.split(' ', 2)[1][len("__NR_"):])

        self.transforms = {
            'PVOID*': (MOD_OUTPUT, 'PVOID'),
            'LONG*': (MOD_OUTPUT, 'LONG'),
            'PBOOLEAN': (MOD_OUTPUT, 'BOOLEAN'),
            'PPS_APC_ROUTINE': (0, 'PVOID'),
            'PIO_APC_ROUTINE': (0, 'PVOID'),
            'PTIMER_APC_ROUTINE': (0, 'PVOID'),
            'ACCESS_MASK': (0, 'ULONG'),
            'DWORD': (0, 'ULONG'),
            'PHANDLE': (MOD_OUTPUT, 'HANDLE'),
            'PULONG': (MOD_OUTPUT, 'ULONG'),
            'PLONG': (MOD_OUTPUT, 'LONG'),
            'ULONG_PTR': (MOD_OUTPUT, 'ULONG'),
            'PSECURITY_DESCRIPTOR': (0, 'PISECURITY_DESCRIPTOR'), # Internal header
            'PACCESS_MASK': (MOD_OUTPUT, 'ACCESS_MASK'),
            'PNTSTATUS': (MOD_OUTPUT, 'NTSTATUS'),
        }

        self.typ_supported = set((
            'HANDLE',
            'PVOID',
            'LONG',
            'ULONG',
            'PULONG',
            'ULONG_PTR',
            'ENUM',
            'BOOLEAN',
            'POBJECT_ATTRIBUTES',
            'PUNICODE_STRING',
            'NTSTATUS',
            'PIO_STATUS_BLOCK',
            'LPGUID',
            'SIZE_T',
            'PSIZE_T',
            'PFILE_BASIC_INFORMATION',
            'LARGE_INTEGER',
            'PLARGE_INTEGER',
            'PTOKEN_PRIVILEGES',
            'LUID',
            'PCLIENT_ID',
            'PGROUP_AFFINITY',
            'WORD',
            'ATOM',
            'PRTL_ATOM',
            'PWSTR',
            'PISECURITY_DESCRIPTOR',
            'PGENERIC_MAPPING',
            'PPRIVILEGE_SET',
            'PSID',
            'ACCESS_MASK',
            'PPORT_MESSAGE',
        ))

        self.enum_supported = set((
            'TOKEN_INFORMATION_CLASS',
            'PROCESSINFOCLASS',
            'KEY_VALUE_INFORMATION_CLASS',
            'SECTION_INHERIT',
            'SEMAPHORE_INFORMATION_CLASS',
            'TIMER_INFORMATION_CLASS',
            'EVENT_INFORMATION_CLASS',
            'OBJECT_INFORMATION_CLASS',
            'ENLISTMENT_INFORMATION_CLASS',
            'SECTION_INFORMATION_CLASS',
            'SYSTEM_INFORMATION_CLASS',
            'KEY_INFORMATION_CLASS',
            'MEMORY_INFORMATION_CLASS',
            'FILE_INFORMATION_CLASS',
            'FS_INFORMATION_CLASS',
            'ATOM_INFORMATION_CLASS',
            'ALPC_PORT_INFORMATION_CLASS',
            'ALPC_MESSAGE_INFORMATION_CLASS',
            'IO_COMPLETION_INFORMATION_CLASS',
            'KEY_SET_INFORMATION_CLASS',
            'MUTANT_INFORMATION_CLASS',
            'TRANSACTION_INFORMATION_CLASS',
            'TRANSACTIONMANAGER_INFORMATION_CLASS',
            'DEBUGOBJECTINFOCLASS',
            'PLUGPLAY_CONTROL_CLASS',
            'PORT_INFORMATION_CLASS',
            'THREADINFOCLASS',
            'TIMER_SET_INFORMATION_CLASS',
            'VDMSERVICECLASS',
            'JOBOBJECTINFOCLASS',
            'RESOURCEMANAGER_INFORMATION_CLASS',
            'WORKERFACTORYINFOCLASS',
            'POWER_ACTION',
            'SYSTEM_POWER_STATE',
            'KPROFILE_SOURCE',
            'AUDIT_EVENT_TYPE',
            'EVENT_TYPE',
            'TOKEN_TYPE',
            'TIMER_TYPE',
            'WAIT_TYPE',
        ))

        # This structure helps to realize semantic connections between arguments
        # For example: a given variable `Count` tells us how many items are present
        # in a given array of `Handles`. This structure allows to express this relation
        # and create specific code to traverse the collection accordingly.
        self.connections = {
            # In this case Handles is an array of count handle
            'WaitForMultipleObjects': {'Handles': ('Count', 'HANDLE')},
            # None here is interpreted as an hex string
            'ReadFile': {'Buffer': ('Length', None)},
            'WriteFile': {'Buffer': ('Length', None)},
            'QueryInformationFile': {'FileInformation': ('Length', None)},
            'QueryKey': {'KeyInformation': ('Length', None)},
            'QueryValueKey': {'KeyValueInformation': ('Length', None)},
            'QueryInformationToken': {'TokenInformation': ('TokenInformationLength', None)},
            'EnumerateValueKey': {'KeyValueInformation': ('Length', None)},
            'QuerySection': {'SecionInformation': ('SecionInformationLength', None)},
            'DeviceIoControlFile': {
                'InputBuffer': ('InputBufferLength', None),
                'OutputBuffer': ('OutputBufferLength', None),
            }
        }

        self.hooks = self.load_hooks()

    def load_hooks(self):
        results = {}
        for hookscript in glob.glob(os.path.join('hooks', '*.hook')):
            # try:
            parser = ConfigParser()
            parser.read(hookscript)
            function = os.path.basename(hookscript.replace('.hook', ''))
            results[function] = parser
            # except Exception, exc:
            #     print>>sys.stderr, exc
            #     print>>sys.stderr, "Unable to parse", hookscript
        return results

    def get_collection_counter(self, func, varname):
        try:
            return self.connections[func[2:]][varname]
        except:
            return (None, None)

    def run(self):
        for filename in glob.glob(os.path.join('headers', '*.h')):
            self.extract_from(filename)

        self.summary()
        self.parser()

    def extract_from(self, fname):
        with open(fname) as f:
            for func, args in self.regex.findall(f.read().replace('\r\n', os.linesep), re.MULTILINE):
                if not func.startswith('Nt') or func not in self.sys_supported:
                    continue

                def strip_comments(s):
                    s = s.strip()
                    pos = s.find('//')

                    if pos >= 0:
                        s = s[:pos-1]

                    return s

                def transform(x):
                    modifier, atype, aname = x

                    if aname[0] == '*':
                        atype += '*'
                        aname = aname[1:]
                    elif aname[-2:] == "[]":
                        aname = aname[:-2]
                        atype += '*'

                    mask, newtype = self.transforms.get(atype, (0, atype))

                    if mask == 0 or (mask == MOD_OUTPUT and modifier & MOD_OUTPUT):
                        atype = newtype

                    return (modifier, atype, aname)

                arguments = []

                for line in self.regex_par.sub('', args[:-2]).split(','):
                    line = strip_comments(line)

                    if not line:
                        continue

                    modifier = 0
                    try:
                        rest, atype, aname = line.rsplit(' ', 2)
                        rest = rest.lower()

                        if 'opt' in rest:
                            modifier |= MOD_OPTIONAL
                        if 'in' in rest:
                            modifier |= MOD_INPUT
                        if 'out' in rest:
                            modifier |= MOD_OUTPUT

                        arguments.append(transform((modifier, atype, aname)))
                    except Exception, exc:
                        # print "// Error while parsing", func, line
                        pass

                self.syscalls[func] = arguments


    def generate(self):
        types = defaultdict(int)

        for func, args in self.syscalls.iteritems():
            if not args:
                continue

            for modifier, atype, aname in args:
                types[atype] += 1

        types = [(v, k) for (k, v) in types.items()]
        types.sort()

        print '/* Types:'
        for count, atype in types:
            print '   ', count, atype
        print '*/'

    def summary(self):
        definitions = '\n'.join(map(lambda x: 'ADDRINT SYS_%s;' % x, sorted(self.syscalls.keys())))
        body1 = '\n'.join(map(lambda x: '  SYS_%s = syscall_name_to_number("%s");' % (x, x), sorted(self.syscalls.keys())))
        body2= '\n'.join(map(lambda x: '  g_syscall_nargs[SYS_%s] = %d;' % (x, len(self.syscalls[x])), sorted(self.syscalls.keys())))

        print '#define __LINE__ 1'
        print '#define __FILE__ "test.c"'
        print '#include "syscalls.h"'

        self.generate()

        print definitions
        print 'void init_common_syscalls()'
        print '{'
        print body1
        print body2
        print '}'
        print

    def parser(self):

        print 'void syscall_before(ADDRINT ip, ADDRINT caller, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)'
        print '{'
        print '  int npars = g_syscall_nargs[num];'
        print '  Log("SYSCALL %ld (%s): 0x%lx 0x%p 0x%p (0x%lx",'
        print '      (long)num, g_syscall_names[num],'
        print '      (unsigned long)ip,'
        print '      caller, (caller != 0)? caller - g_lowaddr : 0 ,'
        print '      (unsigned long)arg0);'
        print '  if(npars>1) Log(", 0x%lx", (unsigned long)arg1);'
        print '  if(npars>2) Log(", 0x%lx", (unsigned long)arg2);'
        print '  if(npars>3) Log(", 0x%lx", (unsigned long)arg3);'
        print '  if(npars>4) Log(", 0x%lx", (unsigned long)arg4);'
        print '  if(npars>5) Log(", 0x%lx", (unsigned long)arg5);'
        print '  Log(")\\n");'
        print '}'

        print 'void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)'
        print '{'
        print '  unsigned long syscall_number = PIN_GetSyscallNumber(ctx, std);'
        print '  uint32_t caller = FindCaller(PIN_GetContextReg(ctx, REG_EBP));'
        print '  if(g_passedEntryPoint && syscall_number < MAX_SYSCALL) {'
        print '    const char *name = g_syscall_names[syscall_number];'
        print '    if (!name) return;'

        print '    ADDRINT a0(PIN_GetSyscallArgument(ctx, std, 0));'
        print '    ADDRINT a1(PIN_GetSyscallArgument(ctx, std, 1));'
        print '    ADDRINT a2(PIN_GetSyscallArgument(ctx, std, 2));'
        print '    ADDRINT a3(PIN_GetSyscallArgument(ctx, std, 3));'
        print '    ADDRINT a4(PIN_GetSyscallArgument(ctx, std, 4));'
        print '    ADDRINT a5(PIN_GetSyscallArgument(ctx, std, 5));'

        # We acquire the lock for all the procedure. Overkill?
        print '    GetLock(&g_write_lock, thread_id+1);'

        print '    Log("[thread id %d] ", thread_id);'
        print '    syscall_before(PIN_GetContextReg(ctx, REG_INST_PTR), (ADDRINT)caller, syscall_number, a0, a1, a2, a3, a4, a5 );'
        print '    syscall_t *sc = &((syscall_t *) v)[thread_id];'
        print '    sc->syscall_number = syscall_number;'
        print '    switch (syscall_number) {'

        uncomplete = set()

        for func, args in self.syscalls.iteritems():
            if not args:
                continue

            print '    case __NR_%s:' % (func)
            print '    {'

            for modifier, atype, aname in args:
                if modifier & MOD_INPUT:
                    mod = 'Input'
                else:
                    mod = 'Output'

                if modifier & MOD_OPTIONAL:
                    mod += ' (optional)'

                print '      W::%s %s; /* %s */' % (atype, aname, mod)

            arguments = ', '.join(["%d, &%s" % (idx, aname) for idx, (modifier, atype, aname) in enumerate(args)])

            self.on_preassign_hook(func)
            print
            print '      syscall_get_arguments(ctx, std, %d, %s);' % (len(args), arguments)
            print
            self.on_postassign_hook(func)

            for modifier, atype, aname in args:
                if self.on_predump_hook(func, modifier, atype, aname):
                    continue

                counter, itertype = self.get_collection_counter(func, aname)

                if atype not in self.typ_supported and \
                   atype not in self.enum_supported and \
                   not counter:
                    uncomplete.add(func)
                    print '      Log("\tINCOMPLETE %s %s\\n");' % (atype, aname)
                    continue

                if modifier & MOD_OPTIONAL:
                    print '      if (!%s)' % (aname)
                    print '      {'
                    print '        Log("\\t%s %s = NULL\\n");' % (atype, aname)
                    print '      } else'

                if atype in self.enum_supported:
                    print '      W::dump_ENUM(%s, "%s");' % (aname, aname)
                else:
                    counter, itertype = self.get_collection_counter(func, aname)

                    if counter:
                        if itertype is not None:
                            print '      for (int i=0; i < %s; i++)' % (counter)
                            print '        W::dump_%s_at(%s[i], i, "%s");' % (itertype, aname, aname)
                        else:
                            print '      W::dump_contents((const char *)%s, %s, "%s");' % (aname, counter, aname)
                    else:
                        print '      W::dump_%s(%s, "%s");' % (atype, aname, aname)

                self.on_postdump_hook(func, modifier, atype, aname)

            print '      break;'
            print '    }'

        print '    default: break;'
        print '    }'

        # Release the giant lock
        print '    ReleaseLock(&g_write_lock);'

        print '  }'
        print '}'

        for func in uncomplete:
            print '//', func

    @hookpresent
    def on_postdump_hook(self, func, modifier, atype, aname, parser):
        return False

    @hookpresent
    def on_predump_hook(self, func, modifier, atype, aname, parser):
        return False

    @hookpresent
    def on_preassign_hook(self, func, parser):
        print parser.get('preassign', 'code')
        try:
            return bool(parser.get('preassign', 'stop'))
        except:
            return False

    @hookpresent
    def on_postassign_hook(self, func, parser):
        print parser.get('postassign', 'code')
        try:
            return bool(parser.get('postassign', 'stop'))
        except:
            return False

SyscallParser().run()
