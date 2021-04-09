#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#define minimum(x, y) ((x) < (y) ? (x) : (y))
#define maximum(x, y) ((x) > (y) ? (x) : (y))
#define MAXMAPSIZE (2200 * 4096)
#define MAXMAPPINGCNT 200
#define randaddr() (((random() % (unsigned long) (endaddr - startaddr)) + (unsigned long) startaddr) & ~0xfff)
#define randaddrlen(addr) ((random() % minimum((unsigned long)(endaddr - (addr)), MAXMAPSIZE)) & ~0xfff)
char tmp[] = "fuzzXXXXXX";

void* randomapping(void* startaddr, void* endaddr) {
  unsigned long mapaddr = randaddr();
  unsigned long maplen = randaddrlen(mapaddr);
  int file = -1;
  void* mapping;
  unsigned long randbits = random();


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
      mapping = mmap((void*) mapaddr, maplen, prot, MAP_PRIVATE | flags, file, offset);
    } else {
      mapping = mmap((void*) mapaddr, maplen, prot, MAP_SHARED | flags, file, offset);
    }
  } else {
    //private & anonymous
    if(randbits & 2) {
      mapping = mmap((void*) mapaddr, maplen, prot, MAP_PRIVATE | MAP_ANONYMOUS | flags, 0, -1);
    } else {
      mapping = mmap((void*) mapaddr, maplen, prot, MAP_SHARED | MAP_ANONYMOUS | flags, 0, -1);
    }
  }

  if(randbits & 16) {
    mlock(mapping, maplen);
  }
  if(randbits & 32) {
    madvise(mapping, maplen, MADV_DONTFORK);
  }
  if(randbits & 64) {
    madvise(mapping, maplen, MADV_WIPEONFORK);
  }
  if(file != -1) {
    close(file);
    unlink(tmp);
  }
}

int performfuzz() {
 void* startaddr;
 void* endaddr;
 long diff;
 do {
   startaddr = (random() & 0xfffffff000) + (void*) 0xf0000000000;
   endaddr = (random() & 0xfffffff000) + (void*) 0xf0000000000;
   diff = (long) (startaddr - endaddr);
   if(diff < 0) diff = -diff;
 } while(diff < MAXMAPSIZE * 20);//what a coincidence
 if(startaddr > endaddr) {
   void* tmp = startaddr;
   startaddr = endaddr;
   endaddr = tmp;
 }

 struct iovec srcvec[1024];
 struct iovec dstvec[1024];
 int vecelems = random() % 1024;
 for(int _ = 0; _ < vecelems; _++) {
   
 }

 for(int _ = 0; _ < (random() % MAXMAPPINGCNT); _++) {
   randomapping(startaddr, endaddr);
 }
 return 0;
}

int main(int argc, char** argv) {
 unsigned long seed;
 if(argc == 1) {
   int rndfd = open("/dev/random", O_RDONLY);
   read(rndfd, &seed, sizeof(unsigned long));
   close(rndfd);
   srandom(seed);
 } else {
   seed = atol(argv[1]);
   srandom(seed);
 }
 int retcode = performfuzz();
 printf("seed: %lx, return code %d\n", seed, retcode);
 return retcode;
}
