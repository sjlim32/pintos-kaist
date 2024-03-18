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
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "kernel/stdio.h"
#include "threads/synch.h"
// #include "threads/vaddr.h"
// #include "threads/palloc.h"
/* ------------------------ */

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* ------ Project 2 ------ */
void check_addr(const char *f_addr);


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

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
//! Project 2 - System calls
void
syscall_handler (struct intr_frame *f UNUSED) {
  //? 시스템콜 호출 번호 - %rax
  //? 인자 - %rdi, $rsi, %rdx, %r10, %r9, %r8
  // printf("######## DBG ######## rdi = { %s }\n", f->R.rdi);
  // printf("######## DBG ######## rsi = { %s }\n", f->R.rsi);
  // printf("######## DBG ######## rdx = { %s }\n", f->R.rdx);
  // printf("######## DBG ######## r10 = { %s }\n", f->R.r10);
  // printf("######## DBG ######## r9 = { %s }\n", f->R.r9);
  // printf("######## DBG ######## r8 = { %s }\n", f->R.r8);

  int sys_number = f->R.rax;

  switch (sys_number) {

  case SYS_HALT:          /* 0 Halt the operating system. */
      halt ();
      break;

  case SYS_EXIT:          /* 1 Terminate this process. */
      exit (f->R.rdi);
      break;

  case SYS_FORK:          /* 2 Clone current process. */
      fork ((char *)f->R.rdi);
      break;

    case SYS_EXEC:
      printf("Performing syscall 3\n");
      // syscall 3 처리
      break;

    case SYS_WAIT:
      printf("Performing syscall 4\n");
      // syscall 4 처리
      break;

    case SYS_CREATE:        /* 5 Create a file. */
      f->R.rax = create((char *)f->R.rdi, f->R.rsi);
      break;

    case SYS_REMOVE:
      printf("Performing syscall 6\n");
      // syscall 6 처리
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
      f->R.rax = write (f->R.rdi, (void *)f->R.rsi, f->R.rdx);
      // printf("######## DBG ######## r10 = { %s }\n", f->R.r10);
      // printf("######## DBG ######## r9 = { %s }\n", f->R.r9);
      // printf("######## DBG ######## r8 = { %s }\n", f->R.r8);
      break;

    case SYS_SEEK:
      printf("Performing syscall 11\n");
      // syscall 11 처리
      break;

    case SYS_TELL:
      printf("Performing syscall 12\n");
      // syscall 12 처리
      break;

    case SYS_CLOSE:         /* 13 Close a file. */
      close(f->R.rsi);
      break;

    default:
      printf ("system call!\n");
      thread_exit ();
      // printf("Unknown syscall number\n");
      // break;
  }
}

/*
  TODO: SYS_EXEC,                    3 Switch current process.
  TODO: SYS_WAIT,                    4 Wait for a child process to die.
  TODO: SYS_REMOVE,                  6 Delete a file.
  TODO: SYS_SEEK,                    11 Change position in a file.
  TODO: SYS_TELL,                    12 Report current position in a file.
*/

void 
halt (void) {

  power_off ();
}

void 
exit (int status) {
  struct thread *curr = thread_current ();
  curr->exit_status = status;

  if (curr->fd_idx > 1) {
    for (int fd = curr->fd_idx; fd > 1; fd--)
      close(fd);
  }

  thread_exit ();
}

pid_t
fork(const char *thread_name) {
  /* 
    %RBX, %RSP, %RBP와 %R12 - %R15 레지스터 복제해야 함
    생성된 자식 프로세스의 pid 반환
    부모 프로세스는 자식 프로세스가 성공적으로 복제되었는지 여부를 알 때까지 fork에서 반환해서는 안 됩니다. 
    즉, 자식 프로세스가 리소스를 복제하지 못하면 부모의 fork() 호출이 TID_ERROR를 반환할 것입니다.
    템플릿은 threads/mmu.c의 pml4_for_each를 사용하여 해당되는 페이지 테이블 구조를 포함한 전체 사용자 메모리 공간을 복사하지만, 
    전달된 pte_for_each_func의 누락된 부분을 채워야 합니다.
    (가상 주소) 참조).
  */
  // int pid = thread_create ();


  // return pid;
}

// int exec (const char *file);
// int wait (pid_t);
bool
create (const char* file, unsigned initial_size) {
  check_addr(file);
  return filesys_create(file, initial_size);
}

int
open(const char *file) {
  check_addr(file);
  struct file *f = filesys_open(file);
  if (f == NULL)
    return -1;

  struct thread *curr = thread_current();
  struct file **fdt = curr->fd_table;

  while (curr->fd_idx < FD_COUNT_LIMIT && fdt[curr->fd_idx])
    curr->fd_idx++;

  if (curr->fd_idx >= FD_COUNT_LIMIT) {
    file_close (f);
    return -1;
  }
  fdt[curr->fd_idx] = f;
  curr->runn_file = curr->fd_idx;

  return curr->fd_idx;
}

void
check_addr(const char *f_addr) {
  if (!is_user_vaddr(f_addr) || f_addr == NULL || !pml4_get_page(thread_current()->pml4, f_addr))
    exit(-1);
}

// bool remove (const char *file);
int
filesize (int fd) {
  int size = -1;

  if (fd <= 1)
    return size;

  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (f == NULL)
    return size;

  size = file_length(f);
  return size;
}

int
read (int fd, void *buffer, unsigned length) {
  int read_size = -1;

  check_addr(buffer);
  if (fd > FD_COUNT_LIMIT || fd == STDOUT_FILENO || fd < 0)
    return read_size;

  struct thread *curr = thread_current ();
  struct file *f = curr->fd_table[fd];

  if (f == NULL)
    return read_size;

  // lock_acquire (&filesys_lock);
  read_size = file_read(f, buffer, length);
  // lock_release (&filesys_lock);

  return read_size;
}

int
write (int fd, const void *buffer, unsigned length) {
  int write_size = -1;

  check_addr(buffer);
  if (fd > FD_COUNT_LIMIT || fd <= 0)
    return write_size;

  if (fd == 1) {
    putbuf (buffer, length);
    return 0;
  }
  else {
    struct thread *curr = thread_current ();
    struct file *f = curr->fd_table[fd];

    if (f == NULL)
      return write_size;

    // lock_acquire (&filesys_lock);
    write_size = file_write(f, buffer, length);
    // lock_release (&filesys_lock);
  }
  return write_size;

}
// void seek (int fd, unsigned position);
// unsigned tell (int fd);
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