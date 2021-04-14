#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#define minimum(x, y) ((x) < (y) ? (x) : (y))
#define maximum(x, y) ((x) > (y) ? (x) : (y))
#define MAXMAPSIZE (2200 * 4096)
#define MAXMAPPINGCNT 200
#define COUNTPOKES (2000)
#define randaddr(start, end) (((random() % (unsigned long) (end - start)) + (unsigned long) start) & ~0xfff)
#define randaddrlen(addr, end) ((random() % minimum((unsigned long)(end - (addr)), MAXMAPSIZE)) & ~0xfff)
char tmp[] = "fuzzXXXXXX";
#define randlong() ((random() << 31) + random()) 
//top 2 bits still not filled, I'm fine with this

int frandmap(void* addr, unsigned int len) {
  unsigned long randbits = randlong();
  int file = -1;

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
    ftruncate(file, len + 40960);
    int offset = random() % 10;
    if(randbits & 2) {
      mmap(addr, len, prot, MAP_PRIVATE | flags, file, offset * 4096);
    } else {
      mmap(addr, len, prot, MAP_SHARED | flags, file, offset * 4096);
    }
  } else {
    //private & anonymous
    if(randbits & 2) {
      mmap(addr, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
      if(randbits & 64) {
        madvise(addr, len, MADV_WIPEONFORK);
	//can only be applid to private anonymous
      }
    } else {
      mmap(addr, len, prot, MAP_SHARED | MAP_ANONYMOUS | flags, -1, 0);
    }
  }

  if(randbits & 16 && len < 0xff000) {
    mlock(addr, len);
  }
  if(randbits & 32) {
    madvise(addr, len, MADV_DONTFORK);
  }
  if(file != -1) {
    close(file);
    unlink(tmp);
    for(int i = 4; i < 10; i++) tmp[i] = 'X';
  }
  return prot;
}

void randomapping(void* startaddr, void* endaddr) {
  unsigned long mapaddr = randaddr(startaddr, endaddr);
  unsigned long maplen = randaddrlen(mapaddr, endaddr);
  frandmap((void*) mapaddr, maplen);
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
    if(random() & 3 == 3) {
      destendaddr = deststartaddr + MAXMAPSIZE;
    } else {
      destendaddr = (void*) (randlong() & 0xffffffff000);
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
      unsigned long len1 = randaddrlen(srcbase, endaddr);
      unsigned long len2 = randaddrlen(dstbase, destendaddr);
      length = minimum(len1, len2);
    } while((srcbase < dstbase && (srcbase + length) > dstbase) || (dstbase < srcbase && (dstbase + length) > srcbase));
    printf("%p %p %lx\n", srcbase, dstbase, length);
    srcvec[_].iov_base = srcbase;
    dstvec[_].iov_base = dstbase;
    srcvec[_].iov_len = length;
    dstvec[_].iov_len = length;
  }
 
  for(int _ = 0; _ < (random() % MAXMAPPINGCNT); _++) {
    randomapping(startaddr, endaddr);
    randomapping(deststartaddr, destendaddr);
  }
 
  long step = (destendaddr - deststartaddr) / 4096 / COUNTPOKES;
  if(step == 0) step = 1;

  void* addr = deststartaddr;
  while(addr < (void*) destendaddr) {
    if(random() & 7) getrandom(addr + (random() % (4096 * 3)), random() % (4096 * ((random() & 15) + 1)), 0);
    //we use getrandom because it'll just EFAULT rather than seg fault if we have no write perms

    float rand01a = (float) random() / (RAND_MAX / 1.0);
    float rand01b = (float) random() / (RAND_MAX / 1.0);
    float normaldist = sqrt(-2 * log(rand01a)) * cos(2 * M_PI * rand01b);
    float betterstep = normaldist * step;
    if(betterstep < 1.0) betterstep = 1.0;
    addr += 4096 * (int) betterstep;
  }

  int result = process_vm_writev(getpid(), srcvec, vecelems, dstvec, vecelems, 0x20);


  return result;
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
  int retcode;
  for(int i = 0; i < 100; i++) {
    retcode = performfuzz();
    printf("seed: 0x%lx, return code %d\n", seed, retcode);
  }
  return retcode;
}
