#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define UNUSED(x)((void)(x))

// Constructor attribute forces function to execute upon injection

void *thread_func(void *data) {
    UNUSED(data);

    while(1) {
        sleep(1);
        printf("I am an injected thread!\n");
    }

    pthread_exit(0);
}

__attribute__((constructor))
void entry() {
    pthread_attr_t attr;
    pthread_t tid;

    pthread_attr_init(&attr);

    if(pthread_create(&tid, &attr, thread_func, NULL) != 0)
        fprintf(stderr, "Failed to launch thread!\n");
}