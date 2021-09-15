#include "hexdump.hh"
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <list>
#include <unistd.h>

int main(int argc, char* argv[]) {
    constexpr int size = 50000;

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

    // insert 50K integers into doubly-linked list
    // in up, down, or random order
    std::list<int> ls;

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

        auto it = ls.begin();
        while (it != ls.end() && *it < idx) {
            ++it;
        }
        ls.insert(it, idx);
    }

    double t1 = cputime();

    printf("inserted %d integers to sorted list in %.09f sec\n", size, t1 - t0);

    // check that list is sorted
    auto it = std::adjacent_find(ls.begin(), ls.end(), std::greater<int>{});
    assert(it == ls.end());
}
