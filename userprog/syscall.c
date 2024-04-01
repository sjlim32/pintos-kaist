#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
/* ------ Project 2 ------ */
#include <string.h>
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "kernel/stdio.h"
#include "threads/synch.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
/* ------ Project 3 ------ */
#include "vm/file.h"
/* ------------------------ */

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

  lock_init(&filesys_lock);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
//! Project 2 - System calls
void
syscall_handler (struct intr_frame *f) {
  //? 시스템콜 호출 번호 - %rax  - 인자 - %rdi, $rsi, %rdx, %r10, %r8, %r9

  int sys_number = f->R.rax;

  switch (sys_number) {

    case SYS_HALT:          /* 0 Halt the operating system. */
      halt();
      break;

    case SYS_EXIT:          /* 1 Terminate this process. */
      exit(f->R.rdi);
      break;

    case SYS_FORK:          /* 2 Clone current process. */
      f->R.rax = fork((char *)f->R.rdi, f);
      break;

    case SYS_EXEC:          /* 3 Switch current process. */
      f->R.rax = exec((char *)f->R.rdi);
      break;

    case SYS_WAIT:          /* 4 Wait for a child process to die. */
      f->R.rax = wait(f->R.rdi);
      break;

    case SYS_CREATE:        /* 5 Create a file. */
      f->R.rax = create((char *)f->R.rdi, f->R.rsi);
      break;

    case SYS_REMOVE:        /* 6 Delete a file. */
      f->R.rax = remove((char *)f->R.rdi);
      break;
    case SYS_OPEN:          /* 7 Open a file. */
      f->R.rax = open((char *)f->R.rdi);
      break;

    case SYS_FILESIZE:      /* 8 Obtain a file's size. */
      f->R.rax = filesize(f->R.rdi);
      break;

    case SYS_READ:          /* 9 Read from a file. */
      f->R.rax = read(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
      break;

    case SYS_WRITE:         /* 10 Write to a file. */
      f->R.rax = write(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
      break;

    case SYS_SEEK:          /* 11 Change position in a file. */
      seek(f->R.rdi, f->R.rsi);
      break;

    case SYS_TELL:          /* 12 Report current position in a file. */
      f->R.rax = tell(f->R.rdi);
      break;

    case SYS_CLOSE:         /* 13 Close a file. */
      close(f->R.rsi);
      break;

    case SYS_MMAP:
      f->R.rax = (uint64_t)mmap ((void *)f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
      break;

    case SYS_MUNMAP:
      munmap((void *)f->R.rdi);
      break;

    case SYS_DUP2:
      f->R.rax = dup2(f->R.rdi, f->R.rsi);
      break;

    default:
      printf ("[ %d ] is Not Define SYS CALL { now thread = %p }\n", (int)f->R.rax, thread_name ());
      thread_exit ();
  }
}

//! ------------------------ Project 2 : Systemcall ------------------------ *//
static void
check_addr (const char *file) {
  void *addr = (void *)file;
#ifdef VM
  if (!addr || !is_user_vaddr (addr)) {
    exit (-1);
  }
  // else {
  //   struct page *find_page = spt_find_page (&thread_current ()->spt, addr);
  //   bool writable = (uint64_t)find_page->va & PTE_W;
  //   if (!writable) {
  //     exit (-1);
  //   }
  // }
#else
  if (!is_user_vaddr (addr) || addr == NULL || !pml4_get_page (thread_current ()->pml4, addr)) {
    exit (-1);
  }
#endif
}

static void
check_with_spt (const char *file) {
  void *addr = (void *)file;
#ifdef VM
  if (!addr || !is_user_vaddr (addr)) {
    exit (-1);
  }
  else {
    struct page *find_page = spt_find_page (&thread_current ()->spt, addr);
    bool writable = (uint64_t)find_page->va & PTE_W;
    if (!writable) {
      exit (-1);
    }
  }

  // struct thread *curr = thread_current ();
  // struct page *find_page = spt_find_page (&curr->spt, (void *)buffer);

  // if (!find_page) {
  //   if ((uint64_t)buffer < USER_STACK && (curr->f_rsp < (uint64_t)buffer)) {
  //     return;
  //   }
  //   exit (-1);
  // }
  // else {
  //   bool writable = (uint64_t)find_page->va & PTE_W;
  //   if (!writable) {
  //     exit (-1);
  //   }
  // }
#else
  if (!is_user_vaddr (buffer) || buffer == NULL || !pml4_get_page (thread_current ()->pml4, buffer)) {
    exit(-1);
  }
#endif
}

static void
halt (void) {
  power_off ();
}

void
exit (int status) {
  struct thread *curr = thread_current ();
  curr->exit_status = status;

  printf ("%s: exit(%d)\n", thread_name(), curr->exit_status);
  // print_spt ();
  thread_exit ();
}

static pid_t
fork (const char *thread_name, struct intr_frame *f) {
  return process_fork(thread_name, f);
}

static int
exec (const char *file) {
  check_addr(file);

  int len = strlen(file) + 1;
  char *file_name = palloc_get_page(PAL_ZERO);

  if (file_name == NULL)
    exit(-1);

  strlcpy(file_name, file, len);

  if (process_exec(file_name) == -1)
    exit(-1);

  palloc_free_page(file_name);

  NOT_REACHED();
}

static int
wait (pid_t pid) {
  return process_wait (pid);
}

static bool
create (const char* file, unsigned initial_size) {
  check_addr(file);
  return filesys_create(file, initial_size);
}

static int
open (const char *file) {
  check_addr(file);
  struct file *f = filesys_open(file);
  if (f == NULL)
    return -1;
  struct thread *curr = thread_current();
  struct file **fdt = curr->fd_table;
  while (curr->fd_idx < FD_COUNT_LIMIT && fdt[curr->fd_idx]) {
    curr->fd_idx++;
  }

  if (curr->fd_idx >= FD_COUNT_LIMIT) {
    file_close (f);
    return -1;
  }

  fdt[curr->fd_idx] = f;
  return curr->fd_idx;
}

static bool
remove (const char *file) {
  check_addr(file);
  return filesys_remove(file);
}

static int
filesize (int fd) {
  if (fd <= 1)
    return -1;

  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (f == NULL)
    return -1;

  int size = file_length(f);
  return size;
}

static int
read (int fd, void *buffer, unsigned length) {
  struct thread *curr = thread_current ();
  check_with_spt (buffer);
  if (fd > FD_COUNT_LIMIT || fd == STDOUT_FILENO || fd < 0) {
    return -1;
  }

  struct file *f = curr->fd_table[fd];

  if (f == NULL) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  int read_size = file_read(f, buffer, length);
  lock_release (&filesys_lock);
  // printf ("file { read } : read = { %s }\n", buffer);
  return read_size;
}

static int
write (int fd, const void *buffer, unsigned length) {
  check_addr (buffer);
  if (fd > FD_COUNT_LIMIT || fd <= 0)
    return -1;

  if (fd == 1) {
    putbuf(buffer, length);
    return 0;
  }
  else {
    struct thread *curr = thread_current ();
    struct file *f = curr->fd_table[fd];

    if (f == NULL)
      return -1;

    lock_acquire (&filesys_lock);
    int write_size = file_write(f, buffer, length);
    lock_release (&filesys_lock);
    return write_size;
  }
}

static void
seek (int fd, unsigned position) {
  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (!is_kernel_vaddr(f))
    exit(-1);

  file_seek(f, position);
}

static unsigned
tell (int fd) {
  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (!is_kernel_vaddr(f))
    exit(-1);

  return file_tell(f);
}

void
close (int fd) {
  if (fd <= 1)
    return;

  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (f == NULL)
    return;

  curr->fd_table[fd] = NULL;
  file_close(f);
}

/*
TODO - file-backed memory
TODO - page fault 발생 시, 즉시 물리 프레임 할당 및 파일에서 메모리로 데이터가 복사되어야 함
TODO - 페이지가 ummapped 또는 swap out 시, 콘텐츠의 모든 변경 사항이 파일에 반영되어야 함

TODO - VM 시스템은 mmap 영역에서 페이지를 lazy load 해야함
TODO - mmap 된 파일 자체를 매핑을 위한 백업 저장소로 사용함
*/

void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
  // printf ("syscall ( mmap ) : START \n");

  struct thread *curr = thread_current ();
  void * succ = NULL;

  if (length < offset || !length || (int)length < 0
    || fd > FD_COUNT_LIMIT || fd <= 1
    || !addr || !is_user_vaddr (addr) || !(pg_ofs (addr) == 0)
    || !(pg_ofs (offset) == 0)
    ) {
    // printf ("syscall ( mmap ) : HERE\n");
    return NULL;
  }

  struct file *file = curr->fd_table[fd];

  if (file == NULL) {
    return NULL;
  }

  struct file *n_f = file_reopen (file);
  // printf ("syscall ( mmap ) : addr, file in kernel = { %p, %p }\n", addr, file);
  // printf ("file { file_back_destroy } : file, n_f = { %p, %p } \n", file, n_f);
  succ = do_mmap (addr, length, writable, n_f, offset);
  return succ;
}

void
munmap (void *addr) {
  /*
  TODO - file-backed memory
  TODO - 페이지가 ummapped 또는 swap out 시, 콘텐츠의 모든 변경 사항이 파일에 반영되어야 함
  */
  do_munmap (addr);
  return;
}


static int
dup2 (int oldfd, int newfd) {
  struct thread *curr = thread_current ();
  struct file **fdt = curr->fd_table;
  struct file *f = file_duplicate (curr->fd_table[oldfd]);

  if (newfd > FD_COUNT_LIMIT || !is_kernel_vaddr(f) || f == NULL) {
    return 1;
  }
  if (fdt[newfd] != NULL) {                   //* newfd 가 이전에 열려있다면, 재사용 되기 전에 닫힘

    close(newfd);
  }
  fdt[newfd] = f;
  return newfd;
}