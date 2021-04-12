#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#define minimum(x, y) ((x) < (y) ? (x) : (y))
#define maximum(x, y) ((x) > (y) ? (x) : (y))
#define MAXMAPSIZE (2200 * 4096)
#define MAXMAPPINGCNT 200
#define randaddr(start, end) (((random() % (unsigned long) (end - start)) + (unsigned long) start) & ~0xfff)
#define randaddrlen(addr, end) ((random() % minimum((unsigned long)(end - (addr)), MAXMAPSIZE)) & ~0xfff)
char tmp[] = "fuzzXXXXXX";
#define randlong() ((random() << 31) + random()) 
//top 2 bits still not filled, I'm fine with this

void* randomapping(void* startaddr, void* endaddr) {
  unsigned long mapaddr = randaddr(startaddr, endaddr);
  unsigned long maplen = randaddrlen(mapaddr, endaddr);
  int file = -1;
  void* mapping;
  unsigned long randbits = randlong();

  int flags = MAP_FIXED;
  int prot = 0;
  if(randbits & 4) {
    prot = PROT_READ;
  }
  if(randbits & 8) {
    prot |= PROT_WRITE;
  }
  if(randbits & 128) {
    flags |= MAP_POPULATE;
  }

  if(randbits & 1) {
    file = mkstemp(tmp);
    ftruncate(file, maplen + 40960);
    int offset = random() % 10;
    if(randbits & 2) {
      mapping = mmap((void*) mapaddr, maplen, prot, MAP_PRIVATE | flags, file, offset * 4096);
    } else {
      mapping = mmap((void*) mapaddr, maplen, prot, MAP_SHARED | flags, file, offset * 4096);
    }
  } else {
    //private & anonymous
    if(randbits & 2) {
      mapping = mmap((void*) mapaddr, maplen, prot, MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
      if(randbits & 64) {
        madvise(mapping, maplen, MADV_WIPEONFORK);
	//can only be applid to private anonymous
      }
    } else {
      mapping = mmap((void*) mapaddr, maplen, prot, MAP_SHARED | MAP_ANONYMOUS | flags, -1, 0);
    }
  }

  if(randbits & 16 && maplen < 0xff000) {
    mlock(mapping, maplen);
  }
  if(randbits & 32) {
    madvise(mapping, maplen, MADV_DONTFORK);
  }
  if(file != -1) {
    close(file);
    unlink(tmp);
    for(int i = 4; i < 10; i++) tmp[i] = 'X';
  }
}

 int performfuzz() {
  void* startaddr;
  void* endaddr;
  void* deststartaddr;
  void* destendaddr;
  long diff, destdiff;
  startaddr = (void*) (randlong() & 0xffffffff000);
  if(random() & 3 != 3) {
    endaddr = (void*) (randlong() & 0xffffffff000);
  } else {
    endaddr = startaddr + MAXMAPSIZE;
  }
  if(startaddr > endaddr) {
    void* tmp = startaddr;
    startaddr = endaddr;
    endaddr = tmp;
  }
  if(random() & 1) {
    deststartaddr = startaddr;
    destendaddr = endaddr;
  } else {
    deststartaddr = (void*) (randlong() & 0xffffffff000);
    if(random() & 3 != 3) {
      destendaddr = (void*) (randlong() & 0xffffffff000);
    } else {
      destendaddr = deststartaddr + MAXMAPSIZE;
    }
    if(deststartaddr > destendaddr) {
      void* tmp = deststartaddr;
      deststartaddr = destendaddr;
      destendaddr = tmp;
    }
  }
 
  struct iovec srcvec[1024];
  struct iovec dstvec[1024];
  int vecelems = random() % 1024;
  for(int _ = 0; _ < vecelems; _++) {
    void* srcbase;
    void* dstbase;
    unsigned long length;
    do {
      srcbase = (void*) (randaddr(startaddr, endaddr));
      dstbase = (void*) (randaddr(deststartaddr, destendaddr));
      length = minimum(randaddrlen(srcbase, endaddr), randaddrlen(dstbase, destendaddr));
    } while((srcbase < dstbase && (srcbase + length) > dstbase) || (dstbase < srcbase && (dstbase + length) > srcbase));
    srcvec[_].iov_base = srcbase;
    dstvec[_].iov_base = dstbase;
    srcvec[_].iov_len = length;
    dstvec[_].iov_len = length;
  }
 
  for(int _ = 0; _ < (random() % MAXMAPPINGCNT); _++) {
    randomapping(startaddr, endaddr);
    randomapping(deststartaddr, destendaddr);
  }
 
  return process_vm_writev(getpid(), srcvec, vecelems, dstvec, vecelems, 0x20);
}

int main(int argc, char** argv) {
  unsigned long seed;
  int seedlog = open("seeds.log", O_CREAT | O_APPEND | O_RDWR, 0777);
  if(argc == 1) {
    getrandom(&seed, sizeof(unsigned long), 0);
    srandom(seed);
  } else {
    seed = strtoll(argv[1], NULL, 16);
    srandom(seed);
  }
  dprintf(seedlog, "0x%lx\n", seed);
  int retcode = performfuzz();
  printf("seed: 0x%lx, return code %d\n", seed, retcode);
  return retcode;
}
