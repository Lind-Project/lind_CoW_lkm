#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#define minimum(x, y) ((x) < (y) ? (x) : (y))
#define maximum(x, y) ((x) > (y) ? (x) : (y))
#define MAXMAPSIZE (2200 * 4096)

void* randomapping(int rndfd, void* startaddr, void* endaddr) {
  unsigned long randread[3];
  read(rndfd, randread, 3 * sizeof(long));
  unsigned long mapaddr = (randread[0] % (unsigned long) (endaddr - startaddr)) + (unsigned long) startaddr;
  unsigned long maplen = randread[1] % minimum((unsigned long)(endaddr - mapaddr), MAXMAPSIZE);

  if(randread[2] & 1) {
    //file backed
    //randomize offset
    if(randread[2] & 2) {
      //private
    } else {
      //shared
    }
  } else {
    //private & anonymous
  }

  if(randread[2] & 4) {
    //read perms
  }
  if(randread[2] & 8) {
    //write perms
  }

  if(randread[2] & 16) {
    //lock mapping
  }
  if(randread[2] & 32) {
    //dontfork mapping
  }
  if(randread[2] & 64) {
    //wipeonfork mapping
  }
  if(randread[2] & 128) {
    //prefaulted mapping
  }
}

int main() {
 int rndfd = open("/dev/random", O_RDONLY);
 close(rndfd);
}
