#ifndef PROC__H_
#define PROC__H_

#define __x86_64__

// libc
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wait.h>
#include <time.h>

// Linux api
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <dirent.h>
#include <dlfcn.h>

// PTrace API
#include <sys/ptrace.h>

// Useful MACROS
#define UNUSED(x)((void)(x))
#define NUMBER_OF_ELEMENTS(x)(sizeof(x) / sizeof(x[0]))

#define MAIN_ARGS const int argc, const char** const argv, const char** const envp
#define UNUSED_MAIN_ARGS UNUSED(argc); UNUSED(argv); UNUSED(envp)

#define MAPS_SIZE 100000

// Intel opcodes
#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

typedef unsigned int uint;

// SO vs ELF compile
#ifdef OPT__PROC_C
    #define IMPORT
#elif defined(__cplusplus)
    #define IMPORT extern "C"
#else
    #define IMPORT extern
#endif

// ptrace reg type
#ifdef ARM
	#define REG_TYPE user_regs
#else
	#define REG_TYPE user_regs_struct
#endif

// Function decs
IMPORT void *ec_malloc(uint size);
IMPORT uint get_file_length(int fd, off_t cur_position);
IMPORT void unload_file(char *file_buffer);
IMPORT char *load_file(const char* const file_name);
IMPORT pid_t find_pid(const char* const process_name);
IMPORT long get_addr(pid_t pid, const char* const index_str);
IMPORT long find_executable_memory(pid_t pid);
IMPORT long get_libc_addr(pid_t pid);
IMPORT long get_libc_func_addr(const char* const func_name);
IMPORT void ptrace_attach(pid_t target);
IMPORT void ptrace_detach(pid_t target);
IMPORT void ptrace_getregs(pid_t target, struct REG_TYPE* regs);
IMPORT void ptrace_cont(pid_t target);
IMPORT void ptrace_setregs(pid_t target, struct REG_TYPE* regs);
IMPORT siginfo_t ptrace_getsiginfo(pid_t target);
IMPORT void ptrace_read(int pid, unsigned long addr, void *vptr, int len);
IMPORT void ptrace_write(int pid, unsigned long addr, void *vptr, int len);
IMPORT void check_target_sig(int pid);
IMPORT unsigned char *find_ret(void *end_of_func);

#endif