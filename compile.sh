gcc -shared proc.c -fPIC -ldl -o bin/libproc.so
cp bin/libproc.so /usr/lib
cp proc.h /usr/include
gcc main.c -Wall -Wextra -lproc -o main