#define PTRACE_GETVRREGS	0x12
#define PTRACE_SETVRREGS	0x13
#define PTRACE_GETEVRREGS	0x14
#define PTRACE_SETEVRREGS	0x15
#define PTRACE_GETREGS64	0x16
#define PTRACE_SETREGS64	0x17
#define PTRACE_GET_DEBUGREG	0x19
#define PTRACE_SET_DEBUGREG	0x1a
#define PTRACE_GETVSRREGS	0x1b
#define PTRACE_SETVSRREGS	0x1c
#define PTRACE_SINGLEBLOCK	0x100

#define PT_GETVRREGS PTRACE_GETVRREGS
#define PT_SETVRREGS PTRACE_SETVRREGS
#define PT_GETEVRREGS PTRACE_GETEVRREGS
#define PT_SETEVRREGS PTRACE_SETEVRREGS
#define PT_GETREGS64 PTRACE_GETREGS64
#define PT_SETREGS64 PTRACE_SETREGS64
#define PT_GET_DEBUGREG PTRACE_GET_DEBUGREG
#define PT_SET_DEBUGREG PTRACE_SET_DEBUGREG
#define PT_GETVSRREGS PTRACE_GETVSRREGS
#define PT_SETVSRREGS PTRACE_SETVSRREGS
#define PT_STEPBLOCK PTRACE_SINGLEBLOCK
