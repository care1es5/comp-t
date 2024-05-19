# Apply enums to SECCOMP constants (mini)
# @author careless
# @category Data Types

from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompileResults
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import *
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import *
from ghidra.program.model.data import *
from ghidra.app.cmd.equate import SetEquateCmd

syscall_x64 = {
    0: "SYS_READ",
    1: "SYS_WRITE",
    2: "SYS_OPEN",
    3: "SYS_CLOSE",
    4: "SYS_NEWSTAT",
    5: "SYS_NEWFSTAT",
    6: "SYS_NEWLSTAT",
    7: "SYS_POLL",
    8: "SYS_LSEEK",
    9: "SYS_MMAP",
    10: "SYS_MPROTECT",
    11: "SYS_MUNMAP",
    12: "SYS_BRK",
    13: "SYS_RT_SIGACTION",
    14: "SYS_RT_SIGPROCMASK",
    15: "SYS_RT_SIGRETURN",
    16: "SYS_IOCTL",
    17: "SYS_PREAD64",
    18: "SYS_PWRITE64",
    19: "SYS_READV",
    20: "SYS_WRITEV",
    21: "SYS_ACCESS",
    22: "SYS_PIPE",
    23: "SYS_SELECT",
    24: "SYS_SCHED_YIELD",
    25: "SYS_MREMAP",
    26: "SYS_MSYNC",
    27: "SYS_MINCORE",
    28: "SYS_MADVISE",
    29: "SYS_SHMGET",
    30: "SYS_SHMAT",
    31: "SYS_SHMCTL",
    32: "SYS_DUP",
    33: "SYS_DUP2",
    34: "SYS_PAUSE",
    35: "SYS_NANOSLEEP",
    36: "SYS_GETITIMER",
    37: "SYS_ALARM",
    38: "SYS_SETITIMER",
    39: "SYS_GETPID",
    40: "SYS_SENDFILE64",
    41: "SYS_SOCKET",
    42: "SYS_CONNECT",
    43: "SYS_ACCEPT",
    44: "SYS_SENDTO",
    45: "SYS_RECVFROM",
    46: "SYS_SENDMSG",
    47: "SYS_RECVMSG",
    48: "SYS_SHUTDOWN",
    49: "SYS_BIND",
    50: "SYS_LISTEN",
    51: "SYS_GETSOCKNAME",
    52: "SYS_GETPEERNAME",
    53: "SYS_SOCKETPAIR",
    54: "SYS_SETSOCKOPT",
    55: "SYS_GETSOCKOPT",
    56: "SYS_CLONE",
    57: "SYS_FORK",
    58: "SYS_VFORK",
    59: "SYS_EXECVE",
    60: "SYS_EXIT",
    61: "SYS_WAIT4",
    62: "SYS_KILL",
    63: "SYS_NEWUNAME",
    64: "SYS_SEMGET",
    65: "SYS_SEMOP",
    66: "SYS_SEMCTL",
    67: "SYS_SHMDT",
    68: "SYS_MSGGET",
    69: "SYS_MSGSND",
    70: "SYS_MSGRCV",
    71: "SYS_MSGCTL",
    72: "SYS_FCNTL",
    73: "SYS_FLOCK",
    74: "SYS_FSYNC",
    75: "SYS_FDATASYNC",
    76: "SYS_TRUNCATE",
    77: "SYS_FTRUNCATE",
    78: "SYS_GETDENTS",
    79: "SYS_GETCWD",
    80: "SYS_CHDIR",
    81: "SYS_FCHDIR",
    82: "SYS_RENAME",
    83: "SYS_MKDIR",
    84: "SYS_RMDIR",
    85: "SYS_CREAT",
    86: "SYS_LINK",
    87: "SYS_UNLINK",
    88: "SYS_SYMLINK",
    89: "SYS_READLINK",
    90: "SYS_CHMOD",
    91: "SYS_FCHMOD",
    92: "SYS_CHOWN",
    93: "SYS_FCHOWN",
    94: "SYS_LCHOWN",
    95: "SYS_UMASK",
    96: "SYS_GETTIMEOFDAY",
    97: "SYS_GETRLIMIT",
    98: "SYS_GETRUSAGE",
    99: "SYS_SYSINFO",
    100: "SYS_TIMES",
    101: "SYS_PTRACE",
    102: "SYS_GETUID",
    103: "SYS_SYSLOG",
    104: "SYS_GETGID",
    105: "SYS_SETUID",
    106: "SYS_SETGID",
    107: "SYS_GETEUID",
    108: "SYS_GETEGID",
    109: "SYS_SETPGID",
    110: "SYS_GETPPID",
    111: "SYS_GETPGRP",
    112: "SYS_SETSID",
    113: "SYS_SETREUID",
    114: "SYS_SETREGID",
    115: "SYS_GETGROUPS",
    116: "SYS_SETGROUPS",
    117: "SYS_SETRESUID",
    118: "SYS_GETRESUID",
    119: "SYS_SETRESGID",
    120: "SYS_GETRESGID",
    121: "SYS_GETPGID",
    122: "SYS_SETFSUID",
    123: "SYS_SETFSGID",
    124: "SYS_GETSID",
    125: "SYS_CAPGET",
    126: "SYS_CAPSET",
    127: "SYS_RT_SIGPENDING",
    128: "SYS_RT_SIGTIMEDWAIT",
    129: "SYS_RT_SIGQUEUEINFO",
    130: "SYS_RT_SIGSUSPEND",
    131: "SYS_SIGALTSTACK",
    132: "SYS_UTIME",
    133: "SYS_MKNOD",
    134: "USELIB",
    135: "SYS_PERSONALITY",
    136: "SYS_USTAT",
    137: "SYS_STATFS",
    138: "SYS_FSTATFS",
    139: "SYS_SYSFS",
    140: "SYS_GETPRIORITY",
    141: "SYS_SETPRIORITY",
    142: "SYS_SCHED_SETPARAM",
    143: "SYS_SCHED_GETPARAM",
    144: "SYS_SCHED_SETSCHEDULER",
    145: "SYS_SCHED_GETSCHEDULER",
    146: "SYS_SCHED_GET_PRIORITY_MAX",
    147: "SYS_SCHED_GET_PRIORITY_MIN",
    148: "SYS_SCHED_RR_GET_INTERVAL",
    149: "SYS_MLOCK",
    150: "SYS_MUNLOCK",
    151: "SYS_MLOCKALL",
    152: "SYS_MUNLOCKALL",
    153: "SYS_VHANGUP",
    154: "SYS_MODIFY_LDT",
    155: "SYS_PIVOT_ROOT",
    156: "SYS_NI_SYSCALL",
    157: "SYS_PRCTL",
    158: "SYS_ARCH_PRCTL",
    159: "SYS_ADJTIMEX",
    160: "SYS_SETRLIMIT",
    161: "SYS_CHROOT",
    162: "SYS_SYNC",
    163: "SYS_ACCT",
    164: "SYS_SETTIMEOFDAY",
    165: "SYS_MOUNT",
    166: "SYS_UMOUNT",
    167: "SYS_SWAPON",
    168: "SYS_SWAPOFF",
    169: "SYS_REBOOT",
    170: "SYS_SETHOSTNAME",
    171: "SYS_SETDOMAINNAME",
    172: "SYS_IOPL",
    173: "SYS_IOPERM",
    174: "CREATE_MODULE",
    175: "SYS_INIT_MODULE",
    176: "SYS_DELETE_MODULE",
    177: "GET_KERNEL_SYMS",
    178: "QUERY_MODULE",
    179: "SYS_QUOTACTL",
    180: "NFSSERVCTL",
    181: "GETPMSG",
    182: "PUTPMSG",
    183: "AFS_SYSCALL",
    184: "TUXCALL",
    185: "SECURITY",
    186: "SYS_GETTID",
    187: "SYS_READAHEAD",
    188: "SYS_SETXATTR",
    189: "SYS_LSETXATTR",
    190: "SYS_FSETXATTR",
    191: "SYS_GETXATTR",
    192: "SYS_LGETXATTR",
    193: "SYS_FGETXATTR",
    194: "SYS_LISTXATTR",
    195: "SYS_LLISTXATTR",
    196: "SYS_FLISTXATTR",
    197: "SYS_REMOVEXATTR",
    198: "SYS_LREMOVEXATTR",
    199: "SYS_FREMOVEXATTR",
    200: "SYS_TKILL",
    201: "SYS_TIME",
    202: "SYS_FUTEX",
    203: "SYS_SCHED_SETAFFINITY",
    204: "SYS_SCHED_GETAFFINITY",
    205: "SET_THREAD_AREA",
    206: "SYS_IO_SETUP",
    207: "SYS_IO_DESTROY",
    208: "SYS_IO_GETEVENTS",
    209: "SYS_IO_SUBMIT",
    210: "SYS_IO_CANCEL",
    211: "GET_THREAD_AREA",
    212: "LOOKUP_DCOOKIE",
    213: "SYS_EPOLL_CREATE",
    214: "EPOLL_CTL_OLD",
    215: "EPOLL_WAIT_OLD",
    216: "SYS_REMAP_FILE_PAGES",
    217: "SYS_GETDENTS64",
    218: "SYS_SET_TID_ADDRESS",
    219: "SYS_RESTART_SYSCALL",
    220: "SYS_SEMTIMEDOP",
    221: "SYS_FADVISE64",
    222: "SYS_TIMER_CREATE",
    223: "SYS_TIMER_SETTIME",
    224: "SYS_TIMER_GETTIME",
    225: "SYS_TIMER_GETOVERRUN",
    226: "SYS_TIMER_DELETE",
    227: "SYS_CLOCK_SETTIME",
    228: "SYS_CLOCK_GETTIME",
    229: "SYS_CLOCK_GETRES",
    230: "SYS_CLOCK_NANOSLEEP",
    231: "SYS_EXIT_GROUP",
    232: "SYS_EPOLL_WAIT",
    233: "SYS_EPOLL_CTL",
    234: "SYS_TGKILL",
    235: "SYS_UTIMES",
    236: "VSERVER",
    237: "SYS_MBIND",
    238: "SYS_SET_MEMPOLICY",
    239: "SYS_GET_MEMPOLICY",
    240: "SYS_MQ_OPEN",
    241: "SYS_MQ_UNLINK",
    242: "SYS_MQ_TIMEDSEND",
    243: "SYS_MQ_TIMEDRECEIVE",
    244: "SYS_MQ_NOTIFY",
    245: "SYS_MQ_GETSETATTR",
    246: "SYS_KEXEC_LOAD",
    247: "SYS_WAITID",
    248: "SYS_ADD_KEY",
    249: "SYS_REQUEST_KEY",
    250: "SYS_KEYCTL",
    251: "SYS_IOPRIO_SET",
    252: "SYS_IOPRIO_GET",
    253: "SYS_INOTIFY_INIT",
    254: "SYS_INOTIFY_ADD_WATCH",
    255: "SYS_INOTIFY_RM_WATCH",
    256: "SYS_MIGRATE_PAGES",
    257: "SYS_OPENAT",
    258: "SYS_MKDIRAT",
    259: "SYS_MKNODAT",
    260: "SYS_FCHOWNAT",
    261: "SYS_FUTIMESAT",
    262: "SYS_NEWFSTATAT",
    263: "SYS_UNLINKAT",
    264: "SYS_RENAMEAT",
    265: "SYS_LINKAT",
    266: "SYS_SYMLINKAT",
    267: "SYS_READLINKAT",
    268: "SYS_FCHMODAT",
    269: "SYS_FACCESSAT",
    270: "SYS_PSELECT6",
    271: "SYS_PPOLL",
    272: "SYS_UNSHARE",
    273: "SYS_SET_ROBUST_LIST",
    274: "SYS_GET_ROBUST_LIST",
    275: "SYS_SPLICE",
    276: "SYS_TEE",
    277: "SYS_SYNC_FILE_RANGE",
    278: "SYS_VMSPLICE",
    279: "SYS_MOVE_PAGES",
    280: "SYS_UTIMENSAT",
    281: "SYS_EPOLL_PWAIT",
    282: "SYS_SIGNALFD",
    283: "SYS_TIMERFD_CREATE",
    284: "SYS_EVENTFD",
    285: "SYS_FALLOCATE",
    286: "SYS_TIMERFD_SETTIME",
    287: "SYS_TIMERFD_GETTIME",
    288: "SYS_ACCEPT4",
    289: "SYS_SIGNALFD4",
    290: "SYS_EVENTFD2",
    291: "SYS_EPOLL_CREATE1",
    292: "SYS_DUP3",
    293: "SYS_PIPE2",
    294: "SYS_INOTIFY_INIT1",
    295: "SYS_PREADV",
    296: "SYS_PWRITEV",
    297: "SYS_RT_TGSIGQUEUEINFO",
    298: "SYS_PERF_EVENT_OPEN",
    299: "SYS_RECVMMSG",
    300: "SYS_FANOTIFY_INIT",
    301: "SYS_FANOTIFY_MARK",
    302: "SYS_PRLIMIT64",
    303: "SYS_NAME_TO_HANDLE_AT",
    304: "SYS_OPEN_BY_HANDLE_AT",
    305: "SYS_CLOCK_ADJTIME",
    306: "SYS_SYNCFS",
    307: "SYS_SENDMMSG",
    308: "SYS_SETNS",
    309: "SYS_GETCPU",
    310: "SYS_PROCESS_VM_READV",
    311: "SYS_PROCESS_VM_WRITEV",
    312: "SYS_KCMP",
    313: "SYS_FINIT_MODULE",
    314: "SYS_SCHED_SETATTR",
    315: "SYS_SCHED_GETATTR",
    316: "SYS_RENAMEAT2",
    317: "SYS_SECCOMP",
    318: "SYS_GETRANDOM",
    319: "SYS_MEMFD_CREATE",
    320: "SYS_KEXEC_FILE_LOAD",
    321: "SYS_BPF",
    322: "SYS_EXECVEAT",
    323: "SYS_USERFAULTFD",
    324: "SYS_MEMBARRIER",
    325: "SYS_MLOCK2",
    326: "SYS_COPY_FILE_RANGE",
    327: "SYS_PREADV2",
    328: "SYS_PWRITEV2",
    329: "SYS_PKEY_MPROTECT",
    330: "SYS_PKEY_ALLOC",
    331: "SYS_PKEY_FREE",
    332: "SYS_STATX",
    333: "SYS_IO_PGETEVENTS",
    334: "SYS_RSEQ",
    424: "SYS_PIDFD_SEND_SIGNAL",
    425: "SYS_IO_URING_SETUP",
    426: "SYS_IO_URING_ENTER",
    427: "SYS_IO_URING_REGISTER",
    428: "SYS_OPEN_TREE",
    429: "SYS_MOVE_MOUNT",
    430: "SYS_FSOPEN",
    431: "SYS_FSCONFIG",
    432: "SYS_FSMOUNT",
    433: "SYS_FSPICK",
    434: "SYS_PIDFD_OPEN",
    435: "SYS_CLONE3",
    436: "SYS_CLOSE_RANGE",
    437: "SYS_OPENAT2",
    438: "SYS_PIDFD_GETFD",
    439: "SYS_FACCESSAT2",
    440: "SYS_PROCESS_MADVISE",
    441: "SYS_EPOLL_PWAIT2",
    442: "SYS_MOUNT_SETATTR",
    443: "SYS_QUOTACTL_FD",
    444: "SYS_LANDLOCK_CREATE_RULESET",
    445: "SYS_LANDLOCK_ADD_RULE",
    446: "SYS_LANDLOCK_RESTRICT_SELF",
    447: "SYS_MEMFD_SECRET",
    448: "SYS_PROCESS_MRELEASE",
    449: "SYS_FUTEX_WAITV",
    450: "SYS_SET_MEMPOLICY_HOME_NODE",
    451: "SYS_CACHESTAT",
    452: "SYS_FCHMODAT2",
    453: "SYS_MAP_SHADOW_STACK",
    454: "SYS_FUTEX_WAKE",
    455: "SYS_FUTEX_WAIT",
    456: "SYS_FUTEX_REQUEUE",
    457: "SYS_STATMOUNT",
    458: "SYS_LISTMOUNT",
    459: "SYS_LSM_GET_SELF_ATTR",
    460: "SYS_LSM_SET_SELF_ATTR",
    461: "SYS_LSM_LIST_MODULES",
}

seccomp_def_actions = {
    0x0: "SCMP_ACT_KILL_THREAD",
    0x0: "SCMP_ACT_KILL",
    0x00030000: "SCMP_ACT_TRAP",
    0x7FC00000: "SCMP_ACT_NOTIFY",
    0x7FFC0000: "SCMP_ACT_LOG",
    0x7FC00000: "SECCOMP_RET_USER_NOTIF",
    0x7FFF0000: "SCMP_ACT_ALLOW",
    0x80000000: "SCMP_ACT_KILL_PROCESS",
}


def search_all(pc):
    listing = currentProgram.getListing()
    instr_list = listing.getInstructions(pc,False)

    action_addr = None
    syscall_addr = None

    for instr in instr_list:
        if action_addr and syscall_addr:
            break
        code = instr.toString()
        mnemonic,op = code.split(" ")
        if mnemonic.find("MOV") != -1:
            src,dst = op.split(",")
            if src.find("RSI") != -1 or src.find("ESI") != -1:
                action_addr = instr.getAddress()
            if src.find("RDX") != -1 or src.find("EDX") != -1:
                syscall_addr = instr.getAddress()
   
    return (action_addr,syscall_addr)


def search_actions(pc):
    
    global skip

    listing = currentProgram.getListing()
    instr_list = listing.getInstructions(pc,False)

    action_addr = None

    for instr in instr_list:
        if action_addr:
            break
        code = instr.toString()
        mnemonic,op = code.split(" ")
        if mnemonic.find("MOV") != -1:
            src,dst = op.split(",")
            if src.find("RDI") != -1 or src.find("EDI") != -1:
                action_addr = instr.getAddress()

        if mnemonic.find("XOR") != -1:
            src,dst = op.split(",")
            if src.find("RDI") != -1 or src.find("EDI") != -1:
                action_addr = instr.getAddress()
                skip = 1

    return action_addr


def resolve_function(pcode):
    if not pcode:
        print("[*] PCODE == NULL")
        return -1

    vnode = pcode.getInput(0)

    if vnode and vnode.isAddress():
        addr = vnode.getAddress()
        if not addr:
            print("[*] VARNODE_ADDRESS == NULL")
            return -1

        symbol = getSymbolAt(addr)
        if not symbol:
            print("[*] SYMBOL @{} == NULL" % (hex(symbol)))
            return -1
        else:
            return symbol.toString()

        func = getFunctionAt(addr)
        if not func:
            print("[*] FUNCTION @{} == NULL" % (hex(func)))
            return -1
        else:
            return func.toString()

    return -1


def populate_seccomp_types(name, dt):
    global syscall_x64
    global seccomp_def_actions

    seccomp_actions = dt.getDataType("%s/seccomp_actions" % (name))

    if not seccomp_actions:
        print("[*] SECCOMP_ACTIONS NOT FOUND! Creating a new DataType...")

        seccomp_actions = EnumDataType("seccomp_actions", 8)

        for k, v in seccomp_def_actions.items():
            seccomp_actions.add(v, k)

        dt.addDataType(seccomp_actions, None)

    syscall_table = dt.getDataType("%s/syscall_x64" %(name))

    if not syscall_table:
        print("[*] SYSCALL_TABLE NOT FOUND! Creating a new DataType...")

        syscall_table = EnumDataType("syscall_x64", 8)

        for k, v in syscall_x64.items():
            syscall_table.add(v, k)

        dt.addDataType(syscall_table, None)

    return (seccomp_actions, syscall_table)


prog_name = currentProgram.getName()
prog_dt = currentProgram.getDataTypeManager()

seccomp_actions, syscall_table = populate_seccomp_types(prog_name, prog_dt)
cur_func = getFunctionContaining(currentAddress)
decomp_opt = DecompileOptions()
decomp_ifc = DecompInterface()
decomp_ifc.setOptions(decomp_opt)
decomp_ifc.openProgram(currentProgram)
decomp_ifc.setSimplificationStyle("decompile")
decomp_func = decomp_ifc.decompileFunction(cur_func, 30, monitor)

highFunction = decomp_func.getHighFunction()

if highFunction:
    iterPcodeOps = highFunction.getPcodeOps()

    def_action = None
    action_addr = None
    syscall_num = None
    syscall_addr = None
    op_idx = None
    skip = None
    while iterPcodeOps.hasNext():
        pcode = iterPcodeOps.next()
        opcode = pcode.getOpcode()
        var = pcode.getInput(0)

        if opcode == PcodeOp.CALL:
            
            resolved_name = resolve_function(pcode)

            # Currently this does not handle the case where the function argument gets implicitly set (ex. XOR R/EDI,R/EDI)
            # I think SetEquate does not support (?) this atm
            if "seccomp_init" in resolved_name:
                action = pcode.getInput(1)
                def_action = action.getOffset()
                op_idx = 1

                action_addr = search_actions(var.getPCAddress())

                if not skip:
                    # Set context
                    ctx_out = pcode.getOutput()
                    ctx_high = ctx_out.getHigh()
                    ctx_high_var = ctx_high.getSymbol()
                    HighFunctionDBUtil.updateDBVariable(ctx_high_var,"ctx", None, SourceType.USER_DEFINED)


            if "seccomp_rule_add" in resolved_name:
                var = pcode.getInput(0)
                ctx = pcode.getInput(1)
                action = pcode.getInput(2)
                syscall = pcode.getInput(3)
                op_idx = 2

                def_action = action.getOffset()
                syscall_num = syscall.getOffset()

                action_addr,syscall_addr = search_all(var.getPCAddress())

            if "seccomp_load" in resolved_name:

                if not skip:
                    # Set status
                    load_out = pcode.getOutput()
                    load_high = load_out.getHigh()
                    load_high_var = load_high.getSymbol()
                    HighFunctionDBUtil.updateDBVariable(load_high_var,"status", None, SourceType.USER_DEFINED)

                
            equateTable = currentProgram.getEquateTable()

            
            if action_addr:
                action_name = seccomp_def_actions[def_action]
                action_equate = equateTable.getEquate(action_name)

                if not action_equate:
                    action_equate = equateTable.createEquate(action_name,def_action)
                
                action_equate.addReference(action_addr,op_idx)

            if syscall_addr:
                syscall_name = syscall_x64[syscall_num]
                syscall_equate = equateTable.getEquate(syscall_name)
                
                if not syscall_equate:
                    syscall_equate = equateTable.createEquate(syscall_name,syscall_num)

                syscall_equate.addReference(syscall_addr,3)



                                    
