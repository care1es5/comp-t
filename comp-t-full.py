# Apply enums to SECCOMP constants (full)
# @author careless
# @category Data Types

from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompileResults
from ghidra.util.task import TaskMonitor
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.pcode import *
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import *
from ghidra.program.model.data import *
from ghidra.app.cmd.equate import SetEquateCmd

from ghidra.util import NumericUtilities

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

seccomp_config_actions = {
    0x0: "SCMP_ACT_KILL_THREAD",
    0x0: "SCMP_ACT_KILL",
    0x00030000: "SCMP_ACT_TRAP",
    0x7FC00000: "SCMP_ACT_NOTIFY",
    0x7FFC0000: "SCMP_ACT_LOG",
    0x7FC00000: "SECCOMP_RET_USER_NOTIF",
    0x7FFF0000: "SCMP_ACT_ALLOW",
    0x80000000: "SCMP_ACT_KILL_PROCESS",
}

seccomp_config_mode = {
    0: "SECCOMP_MODE_DISABLED",
    1: "SECCOMP_MODE_STRICT",
    2: "SECCOMP_MODE_FILTER",
}

seccomp_ret = {
    0x80000000: "SECCOMP_RET_KILL_PROCESS",
    0x00000000: "SECCOMP_RET_KILL",
    0x00030000: "SECCOMP_RET_TRAP",
    0x00050000: "SECCOMP_RET_ERRNO",
    0x7FC00000: "SECCOMP_RET_USER_NOTIF",
    0x7FF00000: "SECCOMP_RET_TRACE",
    0x7FFC0000: "SECCOMP_RET_LOG",
    0x7FFF0000: "SECCOMP_RET_ALLOW",
}

prctl = {
    1: "PR_SET_PDEATHSIG",
    2: "PR_GET_PDEATHSIG",
    3: "PR_GET_DUMPABLE",
    4: "PR_SET_DUMPABLE",
    5: "PR_GET_UNALIGN",
    6: "PR_SET_UNALIGN",
    7: "PR_GET_KEEPCAPS",
    8: "PR_SET_KEEPCAPS",
    9: "PR_GET_FPEMU",
    10: "PR_GET_FPEMU",
    11: "PR_FPEMU_NOPRINT",
    12: "PR_SET_FPEXC",
    13: "PR_GET_TIMING",
    14: "PR_SET_TIMING",
    15: "PR_SET_NAME",
    16: "PR_GET_NAME",
    19: "PR_GET_ENDIAN",
    20: "PR_SET_ENDIAN",
    21: "PR_GET_SECCOMP",
    22: "PR_SET_SECCOMP",
    23: "PR_CAPBSET_READ",
    24: "PR_CAPBSET_DROP",
    25: "PR_GET_TSC",
    26: "PR_SET_TSC",
    27: "PR_GET_SECUREBITS",
    28: "PR_SET_SECUREBITS",
    29: "PR_SET_TIMERSLACK",
    30: "PR_GET_TIMERSLACK",
    30: "PR_GET_TIMERSLACK",
    31: "PR_TASK_PERF_EVENTS_DISABLE",
    32: "PR_TASK_PERF_EVENTS_ENABLE",
    33: "PR_MCE_KILL",
    34: "PR_MCE_KILL_GET",
    35: "PR_SET_MM",
    36: "PR_SET_CHILD_SUBREAPER",
    37: "PR_GET_CHILD_SUBREAPER",
    38: "PR_SET_NO_NEW_PRIVS",
    39: "PR_GET_NO_NEW_PRIVS",
    40: "PR_GET_TID_ADDRESS",
    41: "PR_SET_THP_DISABLE",
    42: "PR_GET_THP_DISABLE",
    43: "PR_MPX_ENABLE_MANAGEMENT",
    44: "PR_MPX_DISABLE_MANAGEMENT",
    45: "PR_SET_FP_MODE",
    46: "PR_GET_FP_MODE",
    47: "PR_CAP_AMBIENT",
    50: "PR_SVE_SET_VL",
    51: "PR_SVE_GET_VL",
    52: "PR_GET_SPECULATION_CTRL",
    53: "PR_SET_SPECULATION_CTRL",
    54: "PR_PAC_RESET_KEYS",
    55: "PR_SET_TAGGED_ADDR_CTRL",
    56: "PR_GET_TAGGED_ADDR_CTRL",
    57: "PR_SET_IO_FLUSHER",
    58: "PR_GET_IO_FLUSHER",
    59: "PR_SET_SYSCALL_USER_DISPATCH",
    60: "PR_PAC_SET_ENABLED_KEYS",
    61: "PR_PAC_GET_ENABLED_KEYS",
    62: "PR_SCHED_CORE",
    63: "PR_SME_SET_VL",
    64: "PR_SME_GET_VL",
    65: "PR_SET_MDWE",
    66: "PR_GET_MDWE",
    67: "PR_SET_MEMORY_MERGE",
    68: "PR_GET_MEMORY_MERGE",
    69: "PR_RISCV_V_SET_CONTROL",
    70: "PR_RISCV_V_GET_CONTROL",
    0x59616D61: "PR_SET_PTRACER",
}


sock_fprog = """
struct sock_filter {
     short code;
     byte jt;
     byte jf;
     dword k;
};

struct sock_fprog{
     unsigned short len;
     struct sock_filter *filter;
};
"""


def search_arguments(pc):
    listing = currentProgram.getListing()
    instr_list = listing.getInstructions(pc, False)

    args1 = None
    args2 = None
    args3 = None

    for instr in instr_list:
        if args2 and args2 and args3:
            break
        code = instr.toString()
        mnemonic, op = code.split(" ")
        if mnemonic.find("MOV") != -1 or mnemonic.find("LEA") != -1:
            src, dst = op.split(",")
            if src.find("RDI") != -1 or src.find("EDI") != -1:
                args1 = instr.getAddress()
            if src.find("RSI") != -1 or src.find("ESI") != -1:
                args2 = instr.getAddress()
            if src.find("RDX") != -1 or src.find("EDX") != -1:
                args3 = instr.getAddress()

    return (args1, args2, args3)


def search_actions(pc):
    listing = currentProgram.getListing()
    instr_list = listing.getInstructions(pc, False)

    action_addr = None

    for instr in instr_list:
        if action_addr:
            break
        code = instr.toString()
        mnemonic, op = code.split(" ")
        if mnemonic.find("MOV") != -1:
            src, dst = op.split(",")
            if src.find("RDI") != -1 or src.find("EDI") != -1:
                action_addr = instr.getAddress()

        if mnemonic.find("XOR") != -1:
            src, dst = op.split(",")
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


def compt_ebpf_disassemble(code, jt, jf, k):
    registers = {
        "A": 0,
        "X": 0,
    }

    # ld [0]
    if code == 0x20 and k == 0:
        return "A = SYCALL_NUMBER"

    # ld [4]
    if code == 0x20 and k == 4:
        return "A = ARCH"

    # jeq
    if code == 0x15:
        if k == 0xC000003E:
            if jt:
                return "if (A == ARCH_X86_64)"
            if jf:
                return "if (A != ARCH_X86_64)"
        else:
            syscall = syscall_x64[k]
            if jt:
                return "if (A == %s) goto ret ALLOW" % syscall
            if jf:
                return "if (A != %s)" % syscall

    # ret
    if code == 0x06:
        status = seccomp_ret[k]

        return "ret %s" % (status)


def compt_verify_prctl(decompilation, sock_fprog_t, sock_filter_t):
    highFunction = decompilation.getHighFunction()

    if highFunction:
        iterPcodeOps = highFunction.getPcodeOps()
        while iterPcodeOps.hasNext():
            pcode = iterPcodeOps.next()
            opcode = pcode.getOpcode()
            var = pcode.getInput(0)

            if opcode == PcodeOp.CALL:
                resolved_name = resolve_function(pcode)
                # check only one with filter mode
                # prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,sock_prog);
                if resolved_name == "prctl":
                    option = pcode.getInput(1)
                    option_value = option.getOffset()
                    option_isAddr = None

                    # check if addr or constant
                    if option.isAddress():
                        option_addr = option.getAddress()
                        data = getDataAt(option_addr)
                        option_data = data.getDefaultValueRepresentation().strip("h")
                        option_value = int(option_data, 16)
                        option_isAddr = True

                    option_name = prctl[option_value]

                    args1, args2, args3 = search_arguments(var.getPCAddress())

                    config_sock = None

                    mode = pcode.getInput(2)
                    mode_value = mode.getOffset()

                    mode_name = None
                    mode_isAddr = None

                    if option_name == "PR_SET_SECCOMP":
                        if mode.isAddress():
                            mode_addr = mode.getAddress()
                            data = getDataAt(mode_addr)
                            mode_data = data.getDefaultValueRepresentation().strip("h")
                            mode_value = int(mode_data, 16)
                            mode_isAddr = True

                        mode_name = seccomp_config_mode[mode_value]

                        if (
                            mode_name == "SECCOMP_MODE_FILTER"
                            or mode_name == "SECCOMP_MODE_STRICT"
                        ):
                            sock_fprog = pcode.getInput(3)
                            # it should (?) be an address
                            if sock_fprog.isAddress():
                                # cast it to struct sock_fprog*
                                sock_high = sock_fprog.getHigh()
                                if sock_high:
                                    sock_high_var = sock_high.getSymbol()
                                    if sock_high_var:
                                        # if local
                                        HighFunctionDBUtil.updateDBVariable(
                                            status_high_var,
                                            "prog",
                                            sock_fprog_t,
                                            SourceType.USER_DEFINED,
                                        )

                            # unique address
                            if sock_fprog.isUnique():
                                pdef = sock_fprog.getDef()
                                # actual vnode address
                                prog = pdef.getInput(1).getAddress()
                                # have to create a new addr otherwise it will complain about insufficient memory
                                start = toAddr(prog.offset)
                                end = toAddr(
                                    prog.offset + (sock_fprog_t.getLength() - 1)
                                )
                                clearListing(start, end)
                                sock_data = createData(start, sock_fprog_t)

                                rule_length = sock_data.getComponent(0).getValue().value

                                print("[*] Number of filters: %s" % (rule_length))

                                sock_ptr = sock_data.getComponent(1)
                                sock_fptr = sock_ptr.getValue()

                                clearListing(sock_fptr, sock_fptr.add(rule_length * 8))

                                sock_filter_list = []
                                for i in range(rule_length):
                                    sf = createData(sock_fptr.add(8 * i), sock_filter_t)
                                    sock_filter_list.append(sf)

                                print("=" * 50)
                                print("CODE  JT   JF      K          Description")
                                print("=" * 50)

                                for ft in sock_filter_list:
                                    code = ft.getComponent(0).getValue().value
                                    jt = ft.getComponent(1).getValue().value
                                    jf = ft.getComponent(2).getValue().value
                                    k = ft.getComponent(3).getValue().value
                                    instr = compt_ebpf_disassemble(code, jt, jf, k)

                                    print(
                                        "0x%02x 0x%02x  0x%02x  0x%02x     %s"
                                        % (code, jt, jf, k, instr)
                                    )

                                print("=" * 50)

                    equateTable = currentProgram.getEquateTable()

                    prctl_equate = equateTable.getEquate(option_name)

                    if not prctl_equate:
                        prctl_equate = equateTable.createEquate(
                            option_name, option_value
                        )

                    if not option_isAddr:
                        prctl_equate.addReference(args1, 1)

                    prctl_equate = equateTable.getEquate(mode_name)

                    if not prctl_equate and mode_name:
                        prctl_equate = equateTable.createEquate(mode_name, mode_value)

                        if not mode_isAddr:
                            prctl_equate.addReference(args2, 1)

                    # set output to status
                    status_out = pcode.getOutput()
                    status_high = status_out.getHigh()
                    status_high_var = status_high.getSymbol()

                    if status_high_var:
                        HighFunctionDBUtil.updateDBVariable(
                            status_high_var, "status", None, SourceType.USER_DEFINED
                        )


def compt_verify_seccomp(decompilation):
    highFunction = decompilation.getHighFunction()

    if highFunction:
        iterPcodeOps = highFunction.getPcodeOps()
        def_action = None
        action_addr = None
        syscall_num = None
        syscall_addr = None
        op_idx = None
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
                        HighFunctionDBUtil.updateDBVariable(
                            ctx_high_var, "ctx", None, SourceType.USER_DEFINED
                        )

                if "seccomp_rule_add" in resolved_name:
                    var = pcode.getInput(0)
                    ctx = pcode.getInput(1)
                    action = pcode.getInput(2)
                    syscall = pcode.getInput(3)
                    op_idx = 2

                    def_action = action.getOffset()
                    syscall_num = syscall.getOffset()

                    _, action_addr, syscall_addr = search_arguments(var.getPCAddress())

                if "seccomp_load" in resolved_name:
                    if not skip:
                        # Set status
                        load_out = pcode.getOutput()
                        load_high = load_out.getHigh()
                        load_high_var = load_high.getSymbol()
                        HighFunctionDBUtil.updateDBVariable(
                            load_high_var, "status", None, SourceType.USER_DEFINED
                        )

            equateTable = currentProgram.getEquateTable()

            if action_addr:
                action_name = seccomp_config_actions[def_action]
                action_equate = equateTable.getEquate(action_name)

                if not action_equate:
                    action_equate = equateTable.createEquate(action_name, def_action)

                action_equate.addReference(action_addr, op_idx)

            if syscall_addr:
                syscall_name = syscall_x64[syscall_num]
                syscall_equate = equateTable.getEquate(syscall_name)

                if not syscall_equate:
                    syscall_equate = equateTable.createEquate(syscall_name, syscall_num)

                syscall_equate.addReference(syscall_addr, 3)


def compt_decompile_function(func_addr):
    decomp_opt = DecompileOptions()
    decomp_ifc = DecompInterface()
    decomp_ifc.setOptions(decomp_opt)
    decomp_ifc.openProgram(currentProgram)
    decomp_ifc.setSimplificationStyle("decompile")
    decomp_func = decomp_ifc.decompileFunction(func_addr, 30, monitor)

    return decomp_func


def compt_populate_types(name, dt):
    seccomp_actions = dt.getDataType("%s/seccomp_actions" % (name))

    if not seccomp_actions:
        print("[*] SECCOMP_ACTIONS NOT FOUND! Creating a new DataType...")

        seccomp_actions = EnumDataType("seccomp_actions", 8)

        for k, v in seccomp_config_actions.items():
            seccomp_actions.add(v, k)

        dt.addDataType(seccomp_actions, None)

    syscall_table = dt.getDataType("%s/syscall_x64" % (name))

    if not syscall_table:
        print("[*] SYSCALL_TABLE NOT FOUND! Creating a new DataType...")

        syscall_table = EnumDataType("syscall_x64", 8)

        for k, v in syscall_x64.items():
            syscall_table.add(v, k)

        dt.addDataType(syscall_table, None)

    seccomp_modes = dt.getDataType("%s/seccomp_mode" % (name))

    if not seccomp_modes:
        print("[*] SECCOMP_MODE NOT FOUND! Creating a new DataType...")

        seccomp_modes = EnumDataType("seccomp_mode", 8)

        for k, v in seccomp_config_mode.items():
            seccomp_modes.add(v, k)

        dt.addDataType(seccomp_modes, None)

    sock_fprogs = dt.getDataType("%s/sock_fprog" % (name))

    if not sock_fprogs:
        print("[*] SOCK_FPROG NOT FOUND! Creating a new DataType...")
        parser = CParser(dt)
        sfprog = parser.parse(sock_fprog)
        sock_fprogs = dt.addDataType(sfprog, None)

    sock_filter = dt.getDataType("%s/sock_filter" % (name))

    return (seccomp_actions, syscall_table, seccomp_modes, sock_fprogs, sock_filter)


prog_name = currentProgram.getName()
prog_dt = currentProgram.getDataTypeManager()

(
    seccomp_actions_t,
    syscall_table_t,
    seccomp_mode_t,
    sock_fprog_t,
    sock_filter_t,
) = compt_populate_types(prog_name, prog_dt)


fmgr = currentProgram.getFunctionManager()
fn = fmgr.getFunctions(True)

prctl_addr = None
seccomp_addr = None
skip = None

for func in fn:
    entry_point = func.getEntryPoint()
    if func.name == "prctl":
        ext_prctl = func.getFunctionThunkAddresses()
        if ext_prctl:
            prctl_addr = ext_prctl[0]
            break

    if func.name == "seccomp_rule_add":
        ext_seccomp = func.getFunctionThunkAddresses()
        if ext_seccomp:
            seccomp_addr = ext_seccomp[0]
            break


if prctl_addr:
    print("[*] Checking [PRCTL] => [PR_SET_SECCOMP]")

    refs = getReferencesTo(prctl_addr)

    prctl_refs = []
    for ref in refs:
        parent_func = getFunctionBefore(ref.fromAddress)

        if parent_func not in prctl_refs:
            prctl_refs.append(parent_func)

    for func in prctl_refs:
        # name = func.getName()
        # prctl_address = func.getEntryPoint()
        decompilation = compt_decompile_function(func)
        compt_verify_prctl(decompilation, sock_fprog_t, sock_filter_t)

if seccomp_addr:
    print("[*] Checking [SECCOMP] => [Userspace Policy]")
    refs = getReferencesTo(seccomp_addr)

    seccomp_refs = []
    for ref in refs:
        parent_func = getFunctionBefore(ref.fromAddress)

        if parent_func not in seccomp_refs:
            seccomp_refs.append(parent_func)

    for func in seccomp_refs:
        # name = func.getName()
        # seccomp_address = func.getEntryPoint()
        decompilation = compt_decompile_function(func)
        compt_verify_seccomp(decompilation)
