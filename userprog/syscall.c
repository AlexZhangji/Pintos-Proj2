#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
 
 
static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static bool sys_create (const char *ufile, unsigned initial_size);
static bool sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static void sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static void sys_close (int handle);
 
static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);
 
/* Serializes file system operations. */
static struct lock fs_lock;
 
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}
 
/* System call handler. */

static void
syscall_handler (struct intr_frame *f)
{
  typedef int syscall_function (int, int, int);
  /* A system call. */
  struct syscall
    {
      size_t arg_cnt;           /* Number of arguments. */
      syscall_function *func;   /* Implementation. */
    };
  /* Table of system calls. */
  static const struct syscall syscall_table[] =
    {
      {0, (syscall_function *) sys_halt},
      {1, (syscall_function *) sys_exit},
      {1, (syscall_function *) sys_exec},
      {1, (syscall_function *) sys_wait},
      {2, (syscall_function *) sys_create},
      {1, (syscall_function *) sys_remove},
      {1, (syscall_function *) sys_open},
      {1, (syscall_function *) sys_filesize},
      {3, (syscall_function *) sys_read},
      {3, (syscall_function *) sys_write},
      {2, (syscall_function *) sys_seek},
      {1, (syscall_function *) sys_tell},
      {1, (syscall_function *) sys_close}
    };
  const struct syscall *sc;
  unsigned call_nr;
  int args[3];

  /* Get the system call. */
  copy_in (&call_nr, f->esp, sizeof call_nr);
  if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
    thread_exit ();
  sc = syscall_table + call_nr;

  /* Get the system call arguments. */
  ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);

  /* Execute the system call,
     and set the return value. */
  f->eax = sc->func (args[0], args[1], args[2]);
  //printf("return from syscall handler\n");
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}
 
/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}
 
/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
 
  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      thread_exit ();
    
}
 
/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
 
  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();
 
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          thread_exit (); 
        }
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}
 
/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}
 
/* Exit system call. */
static int
sys_exit (int exit_code) 
{
  thread_current ()->wait_status->exit_code = exit_code;
  //syscall_exit ();
  thread_exit ();
  NOT_REACHED ();
}
 
/* Exec system call. */
static int
sys_exec (const char *ufile) 
{
/* Add code */
  tid_t tid;
  char *kfile = copy_in_string(ufile);
  
  lock_acquire (&fs_lock);
  tid_t child_tid = process_execute(kfile);
  lock_release (&fs_lock);
  
  palloc_free_page(kfile);
  
  if(child_tid == TID_ERROR)
  {
    thread_exit ();
  }
  return tid;
  thread_exit ();
}
 
/* Wait system call. */
static int
sys_wait (tid_t child) 
{
/* Add code */
  return process_wait (child);
  thread_exit ();
}
 
/* Create system call. */
static bool
sys_create (const char *ufile, unsigned initial_size) 
{
  if(ufile == NULL || !verify_user(ufile)) 
  {
    thread_exit ();
  }
  
  lock_acquire (&fs_lock);
  // for debugging - printf("creating file %s", ufile);
  bool ret = filesys_create(ufile, initial_size);
  lock_release (&fs_lock);
  return ret;
}
 
/* Remove system call. */
static bool
sys_remove (const char *ufile) 
{
  lock_acquire (&fs_lock);
  // for debugging - printf("removing file %s", ufile);
  bool ret = filesys_remove(ufile);
  lock_release (&fs_lock);
  return ret;
}
 
/* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
  {
    struct list_elem elem;      /* List element. */
    struct file *file;          /* File. */
    int handle;                 /* File handle. */
  };
 
/* Open system call. */
static int
sys_open (const char *ufile) 
{
  //printf("in sys_open with file: %s\n", ufile);
  if(ufile == NULL) return -1;  
  if(!verify_user(ufile)) thread_exit ();
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;
  //printf("open 2\n");
 
  fd = malloc (sizeof *fd);
  //printf("open 3\n");
  if (fd != NULL)
    {
      //printf("open 4\n");
      lock_acquire (&fs_lock);
      fd->file = filesys_open (kfile);
    //  printf("open 4.5");
      if (fd->file != NULL)
        {
	//	  printf("open 5\n");
          struct thread *cur = thread_current ();
          handle = fd->handle = cur->next_handle++;
          list_push_front (&cur->fds, &fd->elem);
        }
      else 
	 //   printf("open 6\n");
        free (fd);
      lock_release (&fs_lock);
    }
  //printf("open 7\n");
  palloc_free_page (kfile);
// added for debugging - 
  //printf("HANDLE = %d\n", handle);

  return handle;

}
 
/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor *
lookup_fd (int handle)
{
/* Add code to lookup file descriptor in the current thread's fds */
  struct thread *cur = thread_current();
  struct list_elem *e;

  for (e=list_begin (&cur->fds); e!=list_end(&cur->fds); e=list_next(e))
  {
    struct file_descriptor *fd;
    fd = list_entry (e, struct file_descriptor, elem);
    if (fd->handle == handle)
      return fd;
  }
  thread_exit();
}
 
/* Filesize system call. */
static int
sys_filesize (int handle) 
{
/* Add code */
  struct file_descriptor *fd = lookup_fd(handle);
  lock_acquire (&fs_lock);
  int size = file_length (fd->file);
  lock_release (&fs_lock);
  
  return size;
}
 
/* Read system call. */
static int
sys_read (int handle, void *udst_, unsigned size) 
{
/* Add code */
  uint8_t* udst = udst_;
  if (handle == STDIN_FILENO) //standard in
  {
    int i;
    for (i = 0; i < size; i++)
    {
      udst[i] = input_getc();
    }
    return size; 
  }
  
  if (!verify_user (udst)) 
  {
    thread_exit ();
  }
  struct file_descriptor *fd = lookup_fd(handle);
  lock_acquire(&fs_lock);
  int bytes_read = file_read (fd->file, udst, size);
  lock_release(&fs_lock);
  return bytes_read;
  
  thread_exit ();
}
 
/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size) 
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
    fd = lookup_fd (handle);

  lock_acquire (&fs_lock);
  while (size > 0) 
    {
      /* How much bytes to write to this page? */
      size_t page_left = PGSIZE - pg_ofs (usrc);
      size_t write_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Check that we can touch this user page. */
      if (!verify_user (usrc)) 
        {
          lock_release (&fs_lock);
          thread_exit ();
        }

      /* Do the write. */
      if (handle == STDOUT_FILENO)
        {
          putbuf (usrc, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (fd->file, usrc, write_amt);
      if (retval < 0) 
        {
          if (bytes_written == 0)
            bytes_written = -1;
          break;
        }
      bytes_written += retval;

      /* If it was a short write we're done. */
      if (retval != (off_t) write_amt)
        break;

      /* Advance. */
      usrc += retval;
      size -= retval;
    }
  lock_release (&fs_lock);
 
  return bytes_written;
}
 
/* Seek system call. */
static void
sys_seek (int handle, unsigned position) 
{
 // We probably still need to return an integer to indicate success (0) or failure (-1)
 // if the handle is not valid or if the position is negative, then return -1
/* Add code */
  int return_value = -1;
  
  struct file_descriptor *fd = lookup_fd(handle);
  lock_acquire (&fs_lock);
  file_seek (fd->file, position);
  lock_release (&fs_lock);
}
 
/* Tell system call. */
static int
sys_tell (int handle) 
{
/* Add code */
  struct file_descriptor *fd = lookup_fd(handle);
  lock_acquire (&fs_lock);
  int tell = file_tell (fd->file);
  lock_release (&fs_lock);
  
  return tell;
}
 
/* Close system call. */
static void
sys_close (int handle) 
{
/* Add code */
  //printf("calling sys_close\n");
  struct thread *cur = thread_current();
  struct list_elem *e;

  for (e=list_begin(&cur->fds); e!=list_end(&cur->fds); e = list_next(e))
  {
    struct file_descriptor *fd;
    fd = list_entry(e, struct file_descriptor, elem);
    if(handle == fd->handle)
    {
	  //printf("found file to close");
      lock_acquire (&fs_lock);
      file_close (fd->file);
      lock_release (&fs_lock);
      list_remove(e);
      free(fd);
      return;
    }    
  }
}
 
/* On thread exit, close all open files. */
void
syscall_exit (void) 
{
  // Added code to close all of the thread's open fds
  struct thread *cur = thread_current();
  struct list_elem *e;

  for (e=list_begin(&cur->fds); e!=list_end(&cur->fds); e = list_next(e))
  {
    struct file_descriptor *fd;
    fd = list_entry(e, struct file_descriptor, elem);
    lock_acquire (&fs_lock);
    file_close (fd->file);
    lock_release (&fs_lock);
    free(fd);
  }
  return;
}
