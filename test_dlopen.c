#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define UNUSED(x)((void)(x))

int main(const int argc, const char** const argv, const char** const envp) {
    UNUSED(argc); UNUSED(argv); UNUSED(envp);

    void *handle = NULL;

    if((handle = dlopen("./bin/libso.so", RTLD_LAZY)) == NULL) {
        fprintf(stderr, "Failed to open libso.so\n");
        return (int)EXIT_FAILURE;
    }

    return (int)EXIT_SUCCESS;
}