#define M61_DISABLE 1
#include "m61.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <unordered_map>
#include <vector>
#include <algorithm>


static m61_statistics gstats = {0, 0, 0, 0, 0, 0, 0, 0}; // statistics about memory allocations

struct metadata {
  size_t size; // size of user allocation (8)
  size_t magic; // magic number (8)
  int line; // file line number (4)
  int state; // either 1 for allocate or 2 for freed (4)
  char* payl; // pointer to payload (8)
  const char* file; // file name (8)
  metadata* next; // points to next (8)
  metadata* prev; // points to previous (8)
  size_t pad; // padding for alignment (8)
};

metadata* mhead; // head of active allocations list

// key will be of string type and mapped value will be of size_t type
std::unordered_map<std::string, size_t> m;


/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    metadata *ad = (metadata*)base_malloc(sz + sizeof(metadata) + 1); // allocate extra space

    // check if null or greater than an unsigned long
    if (ad == NULL || sz > (4294967295)) {
      gstats.nfail++;
      gstats.fail_size += sz;
      return nullptr;
    }

    // linked-list manipulation: add
    ad->next = mhead;
    ad->prev = nullptr;
    if (mhead) {
        mhead->prev = ad;
    }
    mhead = ad;

    ad->line = line;
    ad->state = 1; // 1 = alloc
    ad->file = file;
    ad->size = sz;
    ad->magic = 0x84157893401;

    // insert file, line, and allocation size into map or update if already exists
    std::string fileLine = file;
    fileLine = fileLine + ":" + std::to_string(line);
    if (m.empty()) {
      m.insert({fileLine, sz});
    } else {
      m[fileLine] += sz;
    }

    // update stats
    gstats.ntotal++;
    gstats.nactive++;
    gstats.total_size += sz;
    gstats.active_size += sz;
    if (gstats.heap_min == 0) {
      gstats.heap_min = (uintptr_t)ad + sizeof(metadata);
      gstats.heap_max = ((uintptr_t)ad) + sz + sizeof(metadata);
    } else if (((uintptr_t)ad + sizeof(metadata)) < gstats.heap_min) {
      gstats.heap_min = (uintptr_t)ad + sizeof(metadata);
    } else if (gstats.heap_max < (((uintptr_t)ad) + sz + sizeof(metadata))) {
      gstats.heap_max = ((uintptr_t)ad) + sz + sizeof(metadata);
    }

    void *payload = ad + 1; // pointer to payload
    ad->payl = (char*) payload; // sets to payload

    char *end = (char*) payload + sz; // points to the end of allocated block
    *end = 88; // set it equal to a number to be compared to in free

    return ad->payl; // return payload pointer
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void m61_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    if (ptr == NULL) {
       return;
    }

    // check if ptr points to active dynamically-allocated memory
    if (((uintptr_t)ptr) > gstats.heap_max || ((uintptr_t)ptr) < gstats.heap_min) {
       fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n",file, line, ptr);
       abort();
    }

    // pointer arithmetic to get to metadata and to the end of allocated block
    metadata *ad = ((metadata*) ptr) - 1;
    char *end = (char*)ptr + ad->size;

    // check if already freed by comparing with magic number
    if (ad->magic == 0xB0B0B0B0){
      fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n", file, line, ptr);
      abort();
    }

    // marks those that match the memory space pointed to by `ptr`
    metadata* tmp = mhead;
    int ifAlloc = 0;
    while (tmp) {
       if (tmp->payl == ptr) {
           ifAlloc=1;
           break;
       } tmp = tmp->next;
    }

    // check if already allocated and whether pointer is inside a different allocated block
    if (ad->magic != 0x84157893401 || !ad || !ifAlloc) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        metadata* tmp2 = mhead;
        while (tmp2) {
            if ((tmp2->payl < ((char*)ptr)) && (((char*)ptr) < (tmp2->payl + tmp2->size))) {
                size_t offset = (size_t)ptr - (size_t)tmp2->payl;
                fprintf(stderr, "%s:%ld: %p is %zu bytes inside a %zu byte region allocated here\n", file, line-2, ptr, offset, tmp2->size);
            } tmp2 = tmp2->next;
      } abort();
    }

    // check for boundary overwrite
    if (*end != 88) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
        abort();
    }

    // linked-list manipulation: remove
    if (ad->next) {
        ad->next->prev = ad->prev;
    } if (ad->prev) {
        ad->prev->next = ad->next;
    } else {
        mhead = ad->next;
    }

    gstats.active_size -= ad->size;
    gstats.nactive--;

    ad->state = 2; // 2 = freed
    ad->magic = 0xB0B0B0B0;

    base_free(ad);
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, long line) {

    // return a null pointer if too-big size that cannot be allocated
    if ((4294967295 / nmemb) < sz) {
      gstats.nfail++;
      return nullptr;
    }

    void* ptr = m61_malloc(nmemb * sz, file, line);

    if (ptr) {
      memset(ptr, 0, nmemb * sz);
    } return ptr;
}

/// m61_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_get_statistics(m61_statistics* stats) {
    *stats = gstats;
}

/// m61_print_statistics()
///    Print the current memory statistics.

void m61_print_statistics() {
    m61_statistics stats;
    m61_get_statistics(&stats);
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
  // traverse through list and print objects that have been malloced but not freed
  if (mhead != NULL) {
      metadata* tmp = mhead;
      while (tmp != NULL) {
          if (tmp->state == 1) {
              printf("LEAK CHECK: %s:%d: allocated object %p with size %zu\n", tmp->file, tmp->line, tmp->payl,tmp->size);
          } tmp=tmp->next;
      }
   }
}


/// m61_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void m61_print_heavy_hitter_report() {

  std::vector<std::pair<std::string, size_t>>v; // create vector and convert map to it

  for (auto& pair: m) {
      double percentage = ((double)pair.second/(double)gstats.total_size) * 100.0; // calculate percentage of total allocated size
      if (percentage >= 20) { // keep only heavy hitters
        v.push_back(make_pair(pair.first, pair.second));
     }  std::sort(v.begin(), v.end(), std::greater <>()); // sort in descending order
  }

  for (const auto& pair2: v) {
      double sortedPercentage = ((double)pair2.second / (double)gstats.total_size) * 100.0;
      printf("HEAVY HITTER: %s: %zu bytes (~%.1f%%)\n", pair2.first.c_str(), pair2.second, sortedPercentage);
  }
}

