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
#define randlongfull() (((random() << 31) + random()) + random() << 62)
#define xorb() (randlongfull() & randlongfull() & randlongfull() & randlongfull() & randlongfull())
//one in 32 change of each bit being set

//generate a mapping with random characteristics that could affct fork
//these include prot, certain flags, and certain madvise values
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
	//can only be applied to private anonymous mappings
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
  //randomize addresses for source and destination of mappings, making sure we sometimes test overlap
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
 
  //randomize iovec elements
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
    //printf("%p %p %lx\n", srcbase, dstbase, length);
    srcvec[_].iov_base = srcbase;
    dstvec[_].iov_base = dstbase;
    srcvec[_].iov_len = length;
    dstvec[_].iov_len = length;
  }
 
  //generate random mappings to copy from in source, and to overwrite in dest
  for(int _ = 0; _ < (random() % MAXMAPPINGCNT); _++) {
    randomapping(startaddr, endaddr);
    randomapping(deststartaddr, destendaddr);
  }
 
  //reasonable step between pages (to increment addr by each iteration)
  long step = (destendaddr - deststartaddr) / 4096 / COUNTPOKES;
  if(step == 0) step = 1;

  int result;
  //more traditional bit fiddling for fuzzing
  switch(random() & 0xf) {
    default:
      result = process_vm_writev(getpid(), srcvec, vecelems, dstvec, vecelems, 0x20);
      break;
    case 0:
      result = process_vm_writev(getpid() ^ xorb(), srcvec, vecelems, dstvec, vecelems, 0x20);
      break;
    case 1:
      result = process_vm_writev(getpid(), (struct iovec*) ((unsigned long) srcvec ^ xorb()), vecelems, dstvec, vecelems, 0x20);
      break;
    case 2:
      result = process_vm_writev(getpid(), srcvec, vecelems ^ xorb(), dstvec, vecelems, 0x20);
      break;
    case 3:
      result = process_vm_writev(getpid(), srcvec, vecelems, (struct iovec*) ((unsigned long) dstvec ^ xorb()), vecelems, 0x20);
      break;
    case 4:
      result = process_vm_writev(getpid(), srcvec, vecelems, dstvec, vecelems ^ xorb(), 0x20);
      break;
    case 5:
      result = process_vm_writev(getpid(), srcvec, vecelems, dstvec, vecelems, 0x20 ^ xorb());
      break;
  }

  void* addr = deststartaddr;
  while(addr < (void*) destendaddr) {
    //poke at random address range somewhere near addr
    if(random() & 7) getrandom(addr + (random() % (4096 * 3)), random() % (4096 * ((random() & 3) + 1)), 0);
    //we use getrandom because it'll just EFAULT rather than seg fault if we have no write perms

    //generate a random number in a normal distribution
    float rand01a = (float) random() / (RAND_MAX / 1.0);
    float rand01b = (float) random() / (RAND_MAX / 1.0);
    float normaldist = sqrt(-2 * log(rand01a)) * cos(2 * M_PI * rand01b) + 1.0;

    //multiply our step by the random variable in the normal distribuion (of course clamping below by 1)
    //we do this in order to test many mappings but sometimes skip larger swaths in order to test that case as well
    float betterstep = normaldist * step;
    if(betterstep < 1.0) betterstep = 1.0;
    addr += 4096 * (int) betterstep;
  }

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
  //seeding for reproducibility
  int retcode = performfuzz();
  printf("return code for seed 0x%lx is %d\n", seed, retcode);
  return retcode;
}
