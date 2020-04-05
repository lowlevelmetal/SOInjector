#include <stdio.h>
#include <unistd.h>

int main(void) {
    while(1) {
        printf("Inject into me!\n");
        sleep(2);
    }

    return 0;
}