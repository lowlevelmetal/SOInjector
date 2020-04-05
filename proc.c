#define OPT__PROC_C

#include "proc.h"

// Better malloc with error checking
void *ec_malloc(uint size) {
    // Allocate memory
    void *ptr = malloc(size);
    if(!ptr) {
        fprintf(stderr, "Failed to allocate memory: %d bytes", size);
        exit(EXIT_FAILURE);
    }

    // Null out buffer
    memset(ptr, 0, size);

    return ptr;
}

// Get file length
uint get_file_length(int fd, off_t cur_position) {
    if(cur_position != 0) lseek(fd, 0, SEEK_SET);
    uint len = lseek(fd, 0, SEEK_END);
    lseek(fd, cur_position, SEEK_SET);

    return len;
}

// Will define in future!
void unload_file(char *file_buffer) {
    free(file_buffer);
}

// Load file into character buffer
char *load_file(const char* const file_name) {
    uint file_len = 0;
    char *file_buffer = NULL;
    ssize_t ret = 0;

    // Open file
    int fd = open(file_name, O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "Failed to open file!\n");
        return file_buffer;
    }

    // Get file length
    file_len = get_file_length(fd, 0);

    if(file_len > 0) {
        // Create buffer for file
        file_buffer = (char *)ec_malloc(file_len + 16);

        // Read file contents into buffer
        for(uint i = 0; (ret = read(fd, file_buffer + i, 1)) > 0; i++);

        if(ret < 0) {
            fprintf(stderr, "Failed to read file data!\n");

            close(fd);
            free(file_buffer);

            return NULL;
        }

        puts(file_buffer);

    } else
        fprintf(stderr, "Unable to load file: File Empty!\n");

    close(fd);

    return file_buffer;
}

// Convert name of process to its pid
pid_t find_pid(const char* const process_name) {
    struct dirent *cur_dir = NULL;
    DIR *dir_handle = NULL;
    int fd = 0;
    
    char path_buffer[512] = {0};
    char name_buffer[512] = {0};
    char file_buffer[512] = {0};
    char *ptr = NULL;

    // Open handle on proc directory
    if((dir_handle = opendir("/proc/")) == NULL) {
        fprintf(stderr, "Failed to get directory handle!\n");
        return 0;
    }

    // Read inner directories
    while((cur_dir = readdir(dir_handle))) {
        if(cur_dir->d_name[0] == '.' || !atoi(cur_dir->d_name)) continue;

        memset(path_buffer, 0, 512);
        memset(name_buffer, 0, 512);
        memset(file_buffer, 0, 512);

        // Create file path
        sprintf(path_buffer, "/proc/%s/status", cur_dir->d_name);

        // Open file
        if((fd = open(path_buffer, O_RDONLY)) < 0) {
            fprintf(stderr, "Failed to open file!\n");
            return 0;
        }

        // Copy file to buffer
        ssize_t ret = 0;
        for(uint i = 0; (ret = read(fd, file_buffer + i, 1)) > 0 && i < 512; i++);
        if(ret < 0) {
            fprintf(stderr, "error: read()\n");
            return 0;
        }

        // Close file
        close(fd);

        // Locate name string
        if((ptr = strstr(file_buffer, "Name:\t")) == NULL) {
            fprintf(stderr, "strstr()\n");
            return 0;
        }

        // Copy name string
        ptr += strlen("Name:\t");
        for(uint i = 0; ptr[i] != '\n'; i++)
            name_buffer[i] = ptr[i];

        // Compare results
        if(strcmp(name_buffer, process_name) == 0)
            return atoi(cur_dir->d_name);
    }

    return 0;
}

// Get local memory address
long get_addr(pid_t pid, const char* const index_str) {
    void *address = NULL;
    int fd = 0;
    ssize_t ret = 0;

    char file_path[512] = {0};
    char addr_buffer[512] = {0};
    char *file_buffer = ec_malloc(sizeof(char) * MAPS_SIZE);
    char *ptr = NULL;

    // Open maps proc file
    sprintf(file_path, "/proc/%d/maps", pid);

    if((fd = open(file_path, O_RDONLY)) < 0) {
        fprintf(stderr, "Failed to open file!\n");
        free(file_buffer);
        return 0;
    }

    // Read MAPS contents
    for(uint i = 0; (ret = read(fd, file_buffer + i, 1)) > 0 && i < MAPS_SIZE; i++);
    if(ret < 0) {
        fprintf(stderr, "Failed to read file contents!\n");
        close(fd);
        free(file_buffer);
        return 0;
    }

    close(fd);

    // Search for index in file
    if((ptr = strstr(file_buffer, index_str)) == NULL) {
        fprintf(stderr, "Failed to locate addr!\n");
        free(file_buffer);
        return 0;
    }

    // Copy address to local buffer
    while(*ptr != '\n')
        ptr--;

    ptr++;

    for(uint i = 0; ptr[i] != '-'; i++)
        addr_buffer[i] = ptr[i];

    free(file_buffer);

    // Convert and return address(ascii --> long)
    return strtol(addr_buffer, 0, 16);
}

long find_executable_memory(pid_t pid) {
    return get_addr(pid, "r-x");
}

long get_libc_addr(pid_t pid) {
    return get_addr(pid, "libc-");
}

// Get function address from libc
long get_libc_func_addr(const char* const func_name) {
    // Get handle on libc
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if(!handle) {
        fprintf(stderr, "Failed find libc.so.6!\n");
        return 0;
    }

    // Retrieve function address!
    long ret = (long)dlsym(handle, func_name);
    if(!ret)
        fprintf(stderr, "Failed to get function address!\n");

    // close handle
    dlclose(handle);

    return ret;
}

/*
 * ptrace_attach()
 *
 * Use ptrace() to attach to a process. This requires calling waitpid() to
 * determine when the process is ready to be traced.
 *
 * args:
 * - int pid: pid of the process to attach to
 *
 */

void ptrace_attach(pid_t target)
{
	int waitpidstatus;

	if(ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_ATTACH) failed\n");
		exit(EXIT_FAILURE);
	}

	if(waitpid(target, &waitpidstatus, WUNTRACED) != target)
	{
		fprintf(stderr, "waitpid(%d) failed\n", target);
		exit(EXIT_FAILURE);
	}
}

/*
 * ptrace_detach()
 *
 * Detach from a process that is being ptrace()d. Unlike ptrace_cont(), this
 * completely ends our relationship with the target process.
 *
 * args:
 * - int pid: pid of the process to detach from. this process must already be
 *   ptrace()d by us in order for this to work.
 *
 */

void ptrace_detach(pid_t target)
{
	if(ptrace(PTRACE_DETACH, target, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_DETACH) failed\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * ptrace_getregs()
 *
 * Use ptrace() to get a process' current register state.  Uses REG_TYPE
 * preprocessor macro in order to allow for both ARM and x86/x86_64
 * functionality.
 *
 * args:
 * - int pid: pid of the target process
 * - struct REG_TYPE* regs: a struct (either user_regs_struct or user_regs,
 *   depending on architecture) to store the resulting register data in
 *
 */

void ptrace_getregs(pid_t target, struct REG_TYPE* regs)
{
	if(ptrace(PTRACE_GETREGS, target, NULL, regs) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_GETREGS) failed\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * ptrace_cont()
 *
 * Continue the execution of a process being traced using ptrace(). Note that
 * this is different from ptrace_detach(): we still retain control of the
 * target process after this call.
 *
 * args:
 * - int pid: pid of the target process
 *
 */

void ptrace_cont(pid_t target)
{
	struct timespec* sleeptime = (struct timespec *)malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 0;
	sleeptime->tv_nsec = 5000000;

	if(ptrace(PTRACE_CONT, target, NULL, NULL) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_CONT) failed\n");
		exit(EXIT_FAILURE);
	}

	nanosleep(sleeptime, NULL);

	// make sure the target process received SIGTRAP after stopping.
	check_target_sig(target);

    free(sleeptime);
}

/*
 * ptrace_setregs()
 *
 * Use ptrace() to set the target's register state.
 *
 * args:
 * - int pid: pid of the target process
 * - struct REG_TYPE* regs: a struct (either user_regs_struct or user_regs,
 *   depending on architecture) containing the register state to be set in the
 *   target process
 *
 */

void ptrace_setregs(pid_t target, struct REG_TYPE* regs)
{
	if(ptrace(PTRACE_SETREGS, target, NULL, regs) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_SETREGS) failed\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * ptrace_getsiginfo()
 *
 * Use ptrace() to determine what signal was most recently raised by the target
 * process. This is primarily used for to determine whether the target process
 * has segfaulted.
 *
 * args:
 * - int pid: pid of the target process
 *
 * returns:
 * - a siginfo_t containing information about the most recent signal raised by
 *   the target process
 *
 */

siginfo_t ptrace_getsiginfo(pid_t target)
{
	siginfo_t targetsig;
	if(ptrace(PTRACE_GETSIGINFO, target, NULL, &targetsig) == -1)
	{
		fprintf(stderr, "ptrace(PTRACE_GETSIGINFO) failed\n");
		exit(EXIT_FAILURE);
	}
	return targetsig;
}

/*
 * ptrace_read()
 *
 * Use ptrace() to read the contents of a target process' address space.
 *
 * args:
 * - int pid: pid of the target process
 * - unsigned long addr: the address to start reading from
 * - void *vptr: a pointer to a buffer to read data into
 * - int len: the amount of data to read from the target
 *
 */

void ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
	int bytesRead = 0;
	int i = 0;
	long word = 0;
	long *ptr = (long *) vptr;

	while (bytesRead < len)
	{
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
		if(word == -1)
		{
			fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
			exit(EXIT_FAILURE);
		}
		bytesRead += sizeof(word);
		ptr[i++] = word;
	}
}

/*
 * ptrace_write()
 *
 * Use ptrace() to write to the target process' address space.
 *
 * args:
 * - int pid: pid of the target process
 * - unsigned long addr: the address to start writing to
 * - void *vptr: a pointer to a buffer containing the data to be written to the
 *   target's address space
 * - int len: the amount of data to write to the target
 *
 */

void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
	int byteCount = 0;
	long word = 0;

	while (byteCount < len)
	{
		memcpy(&word, vptr + byteCount, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
		if(word == -1)
		{
			fprintf(stderr, "ptrace(PTRACE_POKETEXT) failed\n");
			exit(EXIT_FAILURE);
		}
		byteCount += sizeof(word);
	}
}

/*
 * checktargetsig()
 *
 * Check what signal was most recently returned by the target process being
 * ptrace()d. We expect a SIGTRAP from the target process, so raise an error
 * and exit if we do not receive that signal. The most likely non-SIGTRAP
 * signal for us to receive would be SIGSEGV.
 *
 * args:
 * - int pid: pid of the target process
 *
 */

void check_target_sig(int pid)
{
	// check the signal that the child stopped with.
	siginfo_t targetsig = ptrace_getsiginfo(pid);

	// if it wasn't SIGTRAP, then something bad happened (most likely a
	// segfault).
	if(targetsig.si_signo != SIGTRAP)
	{
		fprintf(stderr, "instead of expected SIGTRAP, target stopped with signal %d: %s\n", targetsig.si_signo, strsignal(targetsig.si_signo));
		fprintf(stderr, "sending process %d a SIGSTOP signal for debugging purposes\n", pid);
		ptrace(PTRACE_CONT, pid, NULL, SIGSTOP);
		exit(EXIT_FAILURE);
	}
}

unsigned char *find_ret(void *end_of_func) {
    unsigned char *ptr = (unsigned char *)end_of_func;
    while(*ptr != INTEL_RET_INSTRUCTION)
        ptr--;

    return ptr;
}