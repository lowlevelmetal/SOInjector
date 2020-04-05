#include <proc.h>

/*
 * injectSharedLibrary()
 *
 * This is the code that will actually be injected into the target process.
 * This code is responsible for loading the shared library into the target
 * process' address space.  First, it calls malloc() to allocate a buffer to
 * hold the filename of the library to be loaded. Then, it calls
 * __libc_dlopen_mode(), libc's implementation of dlopen(), to load the desired
 * shared library. Finally, it calls free() to free the buffer containing the
 * library name. Each time it needs to give control back to the injector
 * process, it breaks back in by executing an "int $3" instruction. See the
 * comments below for more details on how this works.
 *
 */

void inject_shared_library()
{
	// here are the assumptions I'm making about what data will be located
	// where at the time the target executes this code:
	//
	//   rdi = address of malloc() in target process
	//   rsi = address of free() in target process
	//   rdx = address of __libc_dlopen_mode() in target process
	//   rcx = size of the path to the shared library we want to load

	// save addresses of free() and __libc_dlopen_mode() on the stack for later use
	asm(
		// rsi is going to contain the address of free(). it's going to get wiped
		// out by the call to malloc(), so save it on the stack for later
		"push %rsi \n"
		// same thing for rdx, which will contain the address of _dl_open()
		"push %rdx"
	);

	// call malloc() from within the target process
	asm(
		// save previous value of r9, because we're going to use it to call malloc()
		"push %r9 \n"
		// now move the address of malloc() into r9
		"mov %rdi,%r9 \n"
		// choose the amount of memory to allocate with malloc() based on the size
		// of the path to the shared library passed via rcx
		"mov %rcx,%rdi \n"
		// now call r9; malloc()
		"callq *%r9 \n"
		// after returning from malloc(), pop the previous value of r9 off the stack
		"pop %r9 \n"
		// break in so that we can see what malloc() returned
		"int $3"
	);

	// call __libc_dlopen_mode() to load the shared library
	asm(
		// get the address of __libc_dlopen_mode() off of the stack so we can call it
		"pop %rdx \n"
		// as before, save the previous value of r9 on the stack
		"push %r9 \n"
		// copy the address of __libc_dlopen_mode() into r9
		"mov %rdx,%r9 \n"
		// 1st argument to __libc_dlopen_mode(): filename = the address of the buffer returned by malloc()
		"mov %rax,%rdi \n"
		// 2nd argument to __libc_dlopen_mode(): flag = RTLD_LAZY
		"movabs $1,%rsi \n"
		// call __libc_dlopen_mode()
		"callq *%r9 \n"
		// restore old r9 value
		"pop %r9 \n"
		// break in so that we can see what __libc_dlopen_mode() returned
		"int $3"
	);

	// call free() to free the buffer we allocated earlier.
	//
	// Note: I found that if you put a nonzero value in r9, free() seems to
	// interpret that as an address to be freed, even though it's only
	// supposed to take one argument. As a result, I had to call it using a
	// register that's not used as part of the x64 calling convention. I
	// chose rbx.
	asm(
		// at this point, rax should still contain our malloc()d buffer from earlier.
		// we're going to free it, so move rax into rdi to make it the first argument to free().
		"mov %rax,%rdi \n"
		// pop rsi so that we can get the address to free(), which we pushed onto the stack a while ago.
		"pop %rsi \n"
		// save previous rbx value
		"push %rbx \n"
		// load the address of free() into rbx
		"mov %rsi,%rbx \n"
		// zero out rsi, because free() might think that it contains something that should be freed
		"xor %rsi,%rsi \n"
		// break in so that we can check out the arguments right before making the call
		"int $3 \n"
		// call free()
		"callq *%rbx \n"
		// restore previous rbx value
		"pop %rbx"
	);

	// we already overwrote the RET instruction at the end of this function
	// with an INT 3, so at this point the injector will regain control of
	// the target's execution.
}

void inject_so_end(void) {}

void restore_detach(pid_t target, unsigned long addr, void* backup, int datasize, struct REG_TYPE oldregs)
{
	ptrace_write(target, addr, backup, datasize);
	ptrace_setregs(target, &oldregs);
	ptrace_detach(target);
}

// Entry Point
int main(MAIN_ARGS) { UNUSED_MAIN_ARGS;
    printf("Shared Object Injector\nMatthew Todd Geiger\n\n");

    if(argc != 3) {
        fprintf(stderr, "USAGE: %s <TARGET_PROCESS> <SHARED_OBJECT>\n", argv[0]);
        return (int)EXIT_FAILURE;
    }

    // Get pids
    pid_t target_pid = find_pid(argv[1]);
    pid_t this_pid   = find_pid("main");

    if(!target_pid || !this_pid) {
        fprintf(stderr, "Failed to locate pids!\n");
        return (int)EXIT_FAILURE;
    }

    // Find libc addresses
    long target_libc = get_libc_addr(target_pid);
    long this_libc = get_libc_addr(this_pid);

    if(!target_libc || !this_pid) {
        fprintf(stderr, "Failed to find libc addresses!\n");
        return (int)EXIT_FAILURE;
    }

    // Find function addresses
    long this_malloc = get_libc_func_addr("malloc");
    long this_dlopen = get_libc_func_addr("__libc_dlopen_mode");
    long this_free   = get_libc_func_addr("free");

    if(!this_malloc || !this_dlopen || !this_free) {
        fprintf(stderr, "Failed to find function addresses!\n");
        return (int)EXIT_FAILURE;
    }

    long target_malloc = target_libc + (this_malloc - this_libc);
    long target_dlopen = target_libc + (this_dlopen - this_libc);
    long target_free   = target_libc + (this_free - this_libc);

    // Find executable region of memory in target
    long executable_region = find_executable_memory(target_pid);
    if(!executable_region) {
        fprintf(stderr, "Failed to find executable region!\n");
        return (int)EXIT_FAILURE;
    }

    // Calculate function size
    long inject_so_len = (long)inject_so_end - (long)inject_shared_library;
    long shellcode_ret_offset = (long)find_ret(inject_so_end) - (long)inject_shared_library;

    char *file_path_buffer = (char *)ec_malloc(sizeof(char) * (strlen(argv[2]) + 1));
    strcpy(file_path_buffer, argv[2]);

    // Debug
    printf("Our Libc: %p\nTarget Libc: %p\n", (void *)this_libc, (void *)target_libc);
    printf("\nUSER:\nmalloc: %p\ndlopen: %p\nfree: %p\n", (void *)this_malloc, (void *)this_dlopen, (void *)this_free);
    printf("\nTARGET:\nmalloc: %p\ndlopen: %p\nfree: %p\n", (void *)target_malloc, (void *)target_dlopen, (void *)target_free);
    printf("\nExecutable Region: %p\n", (void *)executable_region);
    printf("Shellcode Length: %ld\n", inject_so_len);
    printf("Shellcode RET Instruction offset: %p\n", (void *)shellcode_ret_offset);

    // Setup ptrace and attach to target
    struct user_regs_struct old_regs = {0}, regs = {0}, malloc_regs = {0}, dlopen_regs = {0};
    memset(&old_regs, 0, sizeof(struct user_regs_struct));
    memset(&regs, 0, sizeof(struct user_regs_struct));
    memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
    memset(&dlopen_regs, 0, sizeof(struct user_regs_struct));

    printf("\nAttaching debugger...\n");
    printf("Halting target process..\n");

    ptrace_attach(target_pid);

    ptrace_getregs(target_pid, &regs);
    memcpy(&old_regs, &regs, sizeof(struct user_regs_struct));

    printf("Changing target register data...\n");

    // Setup registers
    regs.rip = executable_region + 2;
    regs.rdi = target_malloc;
    regs.rsi = target_free;
    regs.rdx = target_dlopen;
    regs.rcx = (unsigned long long)strlen(file_path_buffer) + 1;

    ptrace_setregs(target_pid, &regs);

    // Create backup of target
    char *backup_buffer = (char *)ec_malloc(sizeof(char) * inject_so_len);
    ptrace_read(target_pid, executable_region, backup_buffer, inject_so_len * sizeof(char));

    // Create buffer to hold shellcode
    char *shellcode_buffer = (char *)ec_malloc(sizeof(char) * inject_so_len);
    memcpy(shellcode_buffer, inject_shared_library, inject_so_len - 1);

    shellcode_buffer[shellcode_ret_offset] = INTEL_INT3_INSTRUCTION;

    printf("Writing shellcode into executable memory space!\n");

    // Write shellcode to target
    ptrace_write(target_pid, executable_region, shellcode_buffer, inject_so_len);

    printf("Executing shellcode!\n");
    // Start shellcode execution
    ptrace_cont(target_pid);

    ptrace_getregs(target_pid, &malloc_regs);
    long target_buf = 0;
    if((target_buf = malloc_regs.rax) == 0) {
        fprintf(stderr, "SHELLCODE FAILURE: malloc()\n");

        restore_detach(target_pid, executable_region, backup_buffer, inject_so_len, old_regs);

        free(backup_buffer);
        free(shellcode_buffer);
        free(file_path_buffer);

        return (int)EXIT_FAILURE;
    }

    // Write lib path to new memory
    ptrace_write(target_pid, target_buf, file_path_buffer, strlen(file_path_buffer) + 1);

    ptrace_cont(target_pid);

    ptrace_getregs(target_pid, &dlopen_regs);
    if(dlopen_regs.rax == 0) {
        fprintf(stderr, "SHELLCODE FAILURE: dlopen()\n");

        restore_detach(target_pid, executable_region, backup_buffer, inject_so_len, old_regs);

        free(backup_buffer);
        free(shellcode_buffer);
        free(file_path_buffer);

        return (int)EXIT_FAILURE;
    }

    ptrace_cont(target_pid);

    printf("Shellcode injection successfull! Restoring register states and backups\n");

    restore_detach(target_pid, executable_region, backup_buffer, inject_so_len, old_regs);

    free(backup_buffer);
    free(shellcode_buffer);
    free(file_path_buffer);

    // Exit process
    return (int)EXIT_SUCCESS;
}