#include "hexdump.hh"
#include <cstdlib>
#include <cstring>
#include <unistd.h>

int main(int argc, char* argv[]) {
    constexpr int size = 100000000;

    // initialize a very large array of integers
    int* v = new int[size];
    for (int i = 0; i != size; ++i) {
        v[i] = rand();
    }

    // check for access style argument
    enum access_style { access_up, access_down, access_random };
    access_style style = access_up;
    int opt;
    while ((opt = getopt(argc, argv, "rud")) != -1) {
        if (opt == 'r') {
            style = access_random;
        } else if (opt == 'd') {
            style = access_down;
        } else if (opt == 'u') {
            style = access_up;
        }
    }

    double t0 = cputime();

    // access 10M integers in up, down, or random order
    unsigned long sum = 0;
    unsigned long rand_sum = 0;

    for (int i = 0; i != size; ++i) {
        int r = rand() % size;

        int idx = 0;
        if (style == access_up) {
            idx = i;
        } else if (style == access_down) {
            idx = size - i - 1;
        } else if (style == access_random) {
            idx = r;
        }

        sum += v[idx];
        rand_sum += r;
    }

    double t1 = cputime();

    printf("accessed %d integers in %.09f sec\n", size, t1 - t0);
    printf("sum: %lu, rand_sum: %lu\n", sum, rand_sum);
}
