#ifndef TESTSWAP
#define TESTSWAP 0
#endif
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
#include <time.h>

#define MAPSIZE 4096L * 1024 * 32
#define TRIALCNT 16
struct timespec scratchtime;
struct timespec scratchtime2;
struct timespec memcpytime;
struct timespec vmwritevtime;
struct timespec cowtime;

void timespecadd(struct timespec* ts0, struct timespec* ts1, struct timespec* dest) {
  dest->tv_nsec = ts0->tv_nsec + ts1->tv_nsec;
  dest->tv_sec = ts0->tv_sec + ts1->tv_sec;
  dest->tv_sec += dest->tv_nsec / 1000000000;
  dest->tv_nsec = dest->tv_nsec % 1000000000;
}

void timespecsub(struct timespec* ts0, struct timespec* ts1, struct timespec* dest) {
  dest->tv_nsec = ts0->tv_nsec - ts1->tv_nsec;
  dest->tv_sec = ts0->tv_sec - ts1->tv_sec;
  if(dest->tv_nsec < 0) {
    dest->tv_sec -= 1;
    dest->tv_nsec += 1000000000;
  }
}

void pcopy_memcpy(int flags, int fd, int offset) { //private, unpopulated
  char* source = mmap(NULL, MAPSIZE, PROT_READ | PROT_WRITE, flags, fd, offset);
  //unfaulted mapping
  char* dest = mmap(NULL, MAPSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

  clock_gettime(CLOCK_REALTIME, &scratchtime);
  memcpy(dest, source, MAPSIZE);
  clock_gettime(CLOCK_REALTIME, &scratchtime2);
  timespecsub(&scratchtime2, &scratchtime, &scratchtime);
  timespecadd(&scratchtime, &memcpytime, &memcpytime);

  munmap(source, MAPSIZE);
  munmap(dest, MAPSIZE);
}

void pcopy_vmw(int flags, int fd, int offset) { //private, unpopulated
  char* source = mmap(NULL, MAPSIZE, PROT_READ | PROT_WRITE, flags, fd, offset);
  //unfaulted mapping
  char* dest = mmap(NULL, MAPSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  struct iovec input[1] = {source, MAPSIZE};
  struct iovec output[1] = {dest, MAPSIZE};

  clock_gettime(CLOCK_REALTIME, &scratchtime);
  process_vm_writev(getpid(), input, 1, output, 1, 0);
  //memset(dest, 0, MAPSIZE);
  clock_gettime(CLOCK_REALTIME, &scratchtime2);
  timespecsub(&scratchtime2, &scratchtime, &scratchtime);
  timespecadd(&scratchtime, &vmwritevtime, &vmwritevtime);

  munmap(source, MAPSIZE);
  munmap(dest, MAPSIZE);
}

void pcopy_cow(int flags, int fd, int offset) { //private, unpopulated
  char* source = mmap(NULL, MAPSIZE, PROT_READ | PROT_WRITE, flags, fd, offset);
  //unfaulted mapping
  char* dest = mmap(NULL, MAPSIZE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
  struct iovec input[1] = {source, MAPSIZE};
  struct iovec output[1] = {dest, MAPSIZE};

  clock_gettime(CLOCK_REALTIME, &scratchtime);
  process_vm_writev(getpid(), input, 1, output, 1, 0x20);
  //memset(dest, 0, MAPSIZE);
  clock_gettime(CLOCK_REALTIME, &scratchtime2);
  timespecsub(&scratchtime2, &scratchtime, &scratchtime);
  timespecadd(&scratchtime, &cowtime, &cowtime);

  munmap(source, MAPSIZE);
  munmap(dest, MAPSIZE);
}

void pcopy_shared(int fd, int offset) { //private, unpopulated
  char* source = mmap(NULL, MAPSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
  //unfaulted mapping
  char* dest = mmap(NULL, MAPSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);

  clock_gettime(CLOCK_REALTIME, &scratchtime);
  memcpy(dest, source, MAPSIZE);
  clock_gettime(CLOCK_REALTIME, &scratchtime2);
  timespecsub(&scratchtime2, &scratchtime, &scratchtime);
  timespecadd(&scratchtime, &memcpytime, &memcpytime);

  munmap(source, MAPSIZE);
  munmap(dest, MAPSIZE);
}

void wipespecs(void) {
  memcpytime.tv_sec = 0;
  memcpytime.tv_nsec = 0;
  vmwritevtime.tv_sec = 0;
  vmwritevtime.tv_nsec = 0;
  cowtime.tv_sec = 0;
  cowtime.tv_nsec = 0;
}

int main() {
  wipespecs();
  for(int i = 0; i < TRIALCNT; i++) {
    pcopy_memcpy(MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pcopy_vmw(MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pcopy_cow(MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  }
  printf("Timings for anonymous, unfaulted mappings\n");
  printf("---------------------------------------------------------\n");
  printf("memcpy took: %ld.%.9lds\n", memcpytime.tv_sec, memcpytime.tv_nsec);
  printf("vm_writev took: %ld.%.9lds\n", vmwritevtime.tv_sec, vmwritevtime.tv_nsec);
  printf("cow took: %ld.%.9ld\n", cowtime.tv_sec, cowtime.tv_nsec);
  wipespecs();
  printf("---------------------------------------------------------\n");
  for(int i = 0; i < TRIALCNT; i++) {
    pcopy_memcpy(MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    pcopy_vmw(MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    pcopy_cow(MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  }
  printf("Timings for anonymous, prefaulted mappings\n");
  printf("---------------------------------------------------------\n");
  printf("memcpy took: %ld.%.9lds\n", memcpytime.tv_sec, memcpytime.tv_nsec);
  printf("vm_writev took: %ld.%.9lds\n", vmwritevtime.tv_sec, vmwritevtime.tv_nsec);
  printf("cow took: %ld.%.9ld\n", cowtime.tv_sec, cowtime.tv_nsec);
  wipespecs();
  printf("---------------------------------------------------------\n");
  int garbagefd = open("proftest", O_CREAT | O_RDWR, 0777);
  ftruncate(garbagefd, MAPSIZE);
  for(int i = 0; i < TRIALCNT; i++) {
    pcopy_memcpy(MAP_PRIVATE, garbagefd, 0);
    pcopy_vmw(MAP_PRIVATE, garbagefd, 0);
    pcopy_cow(MAP_PRIVATE, garbagefd, 0);
  }
  printf("Timings for private, file backed, unfaulted mappings\n");
  printf("---------------------------------------------------------\n");
  printf("memcpy took: %ld.%.9lds\n", memcpytime.tv_sec, memcpytime.tv_nsec);
  printf("vm_writev took: %ld.%.9lds\n", vmwritevtime.tv_sec, vmwritevtime.tv_nsec);
  printf("cow took: %ld.%.9ld\n", cowtime.tv_sec, cowtime.tv_nsec);
  wipespecs();
  printf("---------------------------------------------------------\n");
  for(int i = 0; i < TRIALCNT; i++) {
    pcopy_memcpy(MAP_PRIVATE | MAP_POPULATE, garbagefd, 0);
    pcopy_vmw(MAP_PRIVATE | MAP_POPULATE, garbagefd, 0);
    pcopy_cow(MAP_PRIVATE | MAP_POPULATE, garbagefd, 0);
  }
  printf("Timings for private, file backed, prefaulted mappings\n");
  printf("---------------------------------------------------------\n");
  printf("memcpy took: %ld.%.9lds\n", memcpytime.tv_sec, memcpytime.tv_nsec);
  printf("vm_writev took: %ld.%.9lds\n", vmwritevtime.tv_sec, vmwritevtime.tv_nsec);
  printf("cow took: %ld.%.9ld\n", cowtime.tv_sec, cowtime.tv_nsec);
  wipespecs();
  printf("---------------------------------------------------------\n");
  for(int i = 0; i < TRIALCNT; i++) {
    pcopy_memcpy(MAP_SHARED, garbagefd, 0);
    pcopy_vmw(MAP_SHARED, garbagefd, 0);
    pcopy_cow(MAP_SHARED, garbagefd, 0);
  }
  printf("Timings for shared, file backed, unfaulted mappings\n");
  printf("---------------------------------------------------------\n");
  printf("memcpy took: %ld.%.9lds\n", memcpytime.tv_sec, memcpytime.tv_nsec);
  printf("vm_writev took: %ld.%.9lds\n", vmwritevtime.tv_sec, vmwritevtime.tv_nsec);
  printf("cow took: %ld.%.9ld\n", cowtime.tv_sec, cowtime.tv_nsec);
  wipespecs();
  printf("---------------------------------------------------------\n");
  for(int i = 0; i < TRIALCNT; i++) {
    pcopy_memcpy(MAP_SHARED | MAP_POPULATE, garbagefd, 0);
    pcopy_vmw(MAP_SHARED | MAP_POPULATE, garbagefd, 0);
    pcopy_cow(MAP_SHARED | MAP_POPULATE, garbagefd, 0);
  }
  printf("Timings for shared, file backed, prefaulted mappings\n");
  printf("---------------------------------------------------------\n");
  printf("memcpy took: %ld.%.9lds\n", memcpytime.tv_sec, memcpytime.tv_nsec);
  printf("vm_writev took: %ld.%.9lds\n", vmwritevtime.tv_sec, vmwritevtime.tv_nsec);
  printf("cow took: %ld.%.9ld\n", cowtime.tv_sec, cowtime.tv_nsec);
  wipespecs();
  printf("---------------------------------------------------------\n");
  for(int i = 0; i < TRIALCNT; i++) {
    pcopy_shared(garbagefd, 0);
  }
  printf("Timings for shared, file backed, prefaulted mappings\n");
  printf("---------------------------------------------------------\n");
  printf("memcpy took: %ld.%.9lds\n", memcpytime.tv_sec, memcpytime.tv_nsec);

  
  unlink("proftest");
  close(garbagefd);
  return 0;
}
