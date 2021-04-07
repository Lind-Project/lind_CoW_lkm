#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <assert.h>

#define MAPSIZE 4096L * 1024 * 200
#define SECONDOFF MAPSIZE * 3 / 8 + 77

void testfilebacked() {
  int testfile1 = open(".test1.txt", O_CREAT | O_TRUNC | O_RDWR, 0777);
  ftruncate(testfile1, 4096);
  write(testfile1, "a", 1);
  char* source = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, testfile1, 0);
  char* dest = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  struct iovec invec[1] = {{source, 4096}};
  struct iovec outvec[1] = {{dest, 4096}};

  process_vm_writev(getpid(), invec, 1, outvec, 1, 0x20);

  dest[0] = 'e';
  assert(source[0] == 'e');

  char* furthertest = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, testfile1, 0);
  assert(furthertest[0] == 'e');

  char* privatesource = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, testfile1, 0);
  struct iovec otherinvec[1] = {{privatesource, 4096}};
  assert(process_vm_writev(getpid(), otherinvec, 1, outvec, 1, 0x20) == 4096);
  assert(privatesource[0] == 'e');
  privatesource[0] == 'q';
  assert(source[0] == 'e');
  munmap(source, 4096);
  munmap(dest, 4096);
  munmap(furthertest, 4096);
  munmap(privatesource, 4096);
  close(testfile1);
}

void testanonymous() {
  char* source = mmap(NULL, MAPSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  for(int i = 0; i < MAPSIZE - 50; i += 4091)
    strcpy(source + i, "Test of cow thingy");
  struct iovec invec[2] = {{source, MAPSIZE/2}, {source + MAPSIZE/2, MAPSIZE/2 + 4096}};
  struct iovec outvec[2] = {{(void*) 0xffff0101000, MAPSIZE/2}, {((void*) 0xffff0101000) + MAPSIZE/2, MAPSIZE/2 + 4096}};
  struct iovec secondoutvec[2] = {{(void*) 0xeffe0101000, MAPSIZE / 2}, {((void*) 0xeffe0101000) + MAPSIZE/2, MAPSIZE/2 + 4096}};

  char* source2 = invec[1].iov_base + SECONDOFF;
  strcpy(source2, "This should be at the second offset");
  assert(process_vm_writev(getpid(), invec, 2, outvec, 2, 0x20) == MAPSIZE + 4096);
  assert(process_vm_writev(getpid(), outvec, 2, secondoutvec, 2, 0x20) == MAPSIZE + 4096);
  *source = 'B';
  *((char*) outvec[0].iov_base) = 'Z';
  assert(((char*) outvec[0].iov_base)[0] == 'Z');
  assert(((char*) secondoutvec[0].iov_base)[0] != 'Z');
  assert(((char*) invec[0].iov_base)[0] != 'Z');
  *source2 = 't';
  assert(!strcmp((char*) secondoutvec[1].iov_base + SECONDOFF, "This should be at the second offset"));
  assert(!strcmp((char*) invec[1].iov_base + SECONDOFF, "this should be at the second offset"));
  munmap(invec[0].iov_base, MAPSIZE);
  munmap(outvec[0].iov_base, MAPSIZE);
  munmap(secondoutvec[0].iov_base, MAPSIZE);
}

void teststack() {
  char stackpage[8192] __attribute__((aligned(4096)))= "This is all stack memory";
  struct iovec invec[1] = {{stackpage, 8192}};
  char* dest = mmap(NULL, 40960, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + 4096;
  struct iovec outvec[1] = {{dest, 8192}};

  assert(process_vm_writev(getpid(), invec, 1, outvec, 1, 0x20) == 8192);
  strcpy(dest, "This is not stack memory");
  assert(!strcmp((char*) stackpage, "This is all stack memory"));
  assert(!strcmp((char*) dest, "This is not stack memory"));
  munmap(dest - 4096, 40960);
}

void testbrk() {
  char* brkpage = sbrk(20480);
  strcpy(brkpage, "This is most definitely break memory");
  struct iovec invec[1] = {{brkpage, 0x3000}};
  char* dest = mmap(NULL, 12288, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  struct iovec outvec[1] = {{dest, 0x3000}};

  assert(process_vm_writev(getpid(), invec, 1, outvec, 1, 0x20) == 0x3000);
  assert(!strcmp((char*) dest, "This is most definitely break memory"));
  strcpy(dest, "This is most definitely not break memory");
  assert(!strcmp((char*) brkpage, "This is most definitely break memory"));
  assert(!strcmp((char*) dest, "This is most definitely not break memory"));
  munmap(dest, 0x3000);
}

void testknownfail() {
  char* source = mmap(NULL, 4096 * 27, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char* dest = mmap(NULL, 4096 * 27, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  struct iovec invec[1] = {{source, 0xe000}};
  struct iovec outvec[1] = {{dest, 0xe000}};
  assert(process_vm_writev(getpid(), invec, 1, outvec, 1, 0x20) == 0xE000);
  struct iovec firstpagevec[1] = {{0, 0xe000}};
  assert(process_vm_writev(getpid(), firstpagevec, 1, outvec, 1, 0x20) == -1);
  assert(process_vm_writev(getpid(), invec, 1, firstpagevec, 1, 0x20) == -1);
  void* garbage = (void*) 0xdeff3321000; //garbage address
  assert(process_vm_writev(getpid(), garbage, 1, outvec, 1, 0x20) == -1);
  assert(process_vm_writev(getpid(), invec, 1, garbage, 1, 0x20) == -1);
  invec[0].iov_base = garbage;
  assert(process_vm_writev(getpid(), invec, 1, outvec, 1, 0x20) == 0);
  struct iovec overvec1[2] = {{dest, 0x6000}, {dest, 0x6000}};
  struct iovec overvec2[1] = {{source, 0x6000}};
  assert(process_vm_writev(getpid(), overvec1, 2, overvec2, 1, 0x20) == -1);//different number of elements
  overvec1[0].iov_base = source + 4096;
  overvec1[1].iov_base = source - 4096;
  assert(process_vm_writev(getpid(), overvec1, 1, overvec2, 1, 0x20) == -1);//overlapping elements
  assert(process_vm_writev(getpid(), overvec1 + 1, 1, overvec2, 1, 0x20) == -1);//overlapping elements
  overvec1[0].iov_base = dest;
  overvec1[0].iov_len = 0x7000;
  assert(process_vm_writev(getpid(), overvec1, 1, overvec2, 1, 0x20) == -1);//different sized corresponding elements
  munmap(source, 4096 * 27);
  munmap(dest, 4096 * 27);
}

void testswappressure() {
  char* source = mmap(NULL, 4096 * 29, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  char* dest = mmap(NULL, 4096 * 29, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  struct iovec invec[1] = {{source, 0xe000}};
  struct iovec outvec[1] = {{dest, 0xe000}};
  strcpy(source, "Soon to be swapped away\n");
  long memcap = 4096 * (sysconf(_SC_AVPHYS_PAGES) + 0x1000); //get available memory, expects swap larger than 16MB
  char* v = mmap(NULL, memcap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0); //crush available memory
  assert(v != MAP_FAILED);
  int result = process_vm_writev(getpid(), invec, 1, outvec, 1, 0x20);
  assert(result == 0xe000);//if not, and working as intended (i.e. no or full swapfile), it's been OOM-reaped by this point
  assert(!strcmp(source, dest));
  munmap(source, 4096 * 29);
  munmap(dest, 4096 * 29);
  munmap(v, memcap);
}

void testmultimapping() {
  int testfile1 = open(".test1.txt", O_CREAT | O_TRUNC | O_RDWR, 0777);
  ftruncate(testfile1, 4096 * 80);
  char* source = mmap(NULL, 4096 * 59, PROT_READ | PROT_WRITE, MAP_SHARED, testfile1, 0);
  char* sourcepart2 = mmap(source + 4096 * 42, 4096 * 17, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  char* dest = mmap(NULL, 4096 * 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  struct iovec invec[1] = {{source + 33 * 4096, 4096 * 20}};
  struct iovec outvec[1] = {{dest, 4096 * 20}};
  char* printloc1 = source + 38 * 4096;
  char* printloc2 = source + 44 * 4096;
  char* printloc3 = source + 49 * 4096;
  char* dprintloc1 = dest + 5 * 4096;
  char* dprintloc2 = dest + 11 * 4096;
  char* dprintloc3 = dest + 16 * 4096;
  strcpy(printloc1, "part of file backing now!\n");
  strcpy(printloc2, "part of anonymous backing!\n");
  strcpy(printloc3, "second part of anonymous backing!\n");

  process_vm_writev(getpid(), invec, 1, outvec, 1, 0x20);

  assert(!strcmp(dprintloc1, "part of file backing now!\n"));
  assert(!strcmp(dprintloc2, "part of anonymous backing!\n"));
  assert(!strcmp(dprintloc3, "second part of anonymous backing!\n"));
  strcpy(dprintloc1, "heart of file backing now!\n");
  assert(!strcmp(printloc1, "heart of file backing now!\n"));
  strcpy(dprintloc2, "heart of anonymous backing!\n");

  munmap(dest + 4096 * 12, 4096 * 2); //gap in mapping
  munmap(dest + 4096 * 9, 4096); //gap in mapping
  process_vm_writev(getpid(), invec, 1, outvec, 1, 0x20);
  assert(!strcmp(printloc1, "heart of file backing now!\n"));
  assert(strcmp(printloc2, "heart of anonymous backing!\n"));
  assert(!strcmp(printloc3, "second part of anonymous backing!\n"));
  //check that the file actually changed

  munmap(source, 4096 * 59);
}

void testmisc() {
  //then have remapping of previous
}

int main() {
  testknownfail();

  testfilebacked();
  testanonymous();
  teststack();
  //would've tested malloc but it's not that useful to us here as we'd only be copying part of the allocation, and probably wouldn't work as static address data would differ
  testbrk();
  testmultimapping();
  testswappressure();
  return 0;
}
