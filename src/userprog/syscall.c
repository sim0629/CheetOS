#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static uint8_t get_user_byte (const uint8_t *addr);
static void put_user_byte (uint8_t *addr, uint8_t value);
static int get_user_int (const int *addr);
static void put_user_int (int *addr, int value);
static void check_user_string (const char *str);
static void check_user_buffer (const void *buffer, size_t size, bool writable);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
sys_halt (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}

static void
sys_exit (struct intr_frame *f)
{
  int *p = f->esp;
  int code = get_user_int (++p);
  process_exit (code);
}

static void
sys_exec (struct intr_frame *f)
{
  int *p = f->esp;
  const char *cmdline = (const char *)get_user_int (++p);
  check_user_string (cmdline);
  f->eax = process_execute (cmdline);
}

static void
sys_wait (struct intr_frame *f)
{
  int *p = f->esp;
  pid_t pid = get_user_int (++p);
  f->eax = process_wait (pid);
}

static void
sys_create (struct intr_frame *f)
{
  int *p = f->esp;
  const char *file = (const char *)get_user_int (++p);
  unsigned initial_size = (unsigned)get_user_int (++p);
  check_user_string (file);
  lock_acquire (&filesys_mutex);
  f->eax = filesys_create (file, initial_size);
  lock_release (&filesys_mutex);
}

static void
sys_remove (struct intr_frame *f)
{
  int *p = f->esp;
  const char *file = (const char *)get_user_int (++p);
  check_user_string (file);
  lock_acquire (&filesys_mutex);
  f->eax = filesys_remove (file);
  lock_release (&filesys_mutex);
}

static void
sys_open (struct intr_frame *f)
{
  int *p = f->esp;
  const char *path = (const char *)get_user_int (++p);
  check_user_string (path);
  lock_acquire (&filesys_mutex);
  {
#ifdef FILESYS
    bool is_directory = false;
    struct inode *inode = filesys_open_inode (path, &is_directory);
    struct file *fp;
    int fd = FD_ERROR;
    if (is_directory)
      fp = (struct file *)dir_open (inode);
    else
      fp = file_open (inode);
    fd = process_alloc_fd (fp, is_directory);
    if (fd == FD_ERROR)
      {
        if (is_directory)
          dir_close ((struct dir *)fp);
        else
          file_close (fp);
      }
    f->eax = fd;
#else
    struct file *fp = filesys_open (path);
    int fd = process_alloc_fd (fp);
    if (fd == FD_ERROR)
      file_close (fp);
    f->eax = fd;
#endif
  }
  lock_release (&filesys_mutex);
}

static void
sys_filesize (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  lock_acquire (&filesys_mutex);
  {
    struct file *fp = process_get_file (fd);
    if (fp != NULL)
      f->eax = file_length (fp);
  }
  lock_release (&filesys_mutex);
}

static void
sys_read (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  void *buffer = (void *)get_user_int (++p);
  unsigned size = (unsigned)get_user_int (++p);

  if (size == 0)
    {
      f->eax = 0;
      return;
    }

  if (fd == STDIN_FILENO)
    {
      unsigned i;
      for (i = 0; i < size; i++)
        put_user_byte ((uint8_t *)buffer + i, input_getc ());
      f->eax = i;
      return;
    }

  check_user_buffer (buffer, size, true);

  lock_acquire (&filesys_mutex);
  {
    struct file *fp = process_get_file (fd);
    if (fp != NULL)
      f->eax = file_read (fp, buffer, size);
  }
  lock_release (&filesys_mutex);
}

static void
sys_write (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  const void *buffer = (const void *)get_user_int (++p);
  unsigned size = (unsigned)get_user_int (++p);

  if (size == 0)
    {
      f->eax = 0;
      return;
    }

  check_user_buffer (buffer, size, false);

  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      f->eax = size;
      return;
    }

  lock_acquire (&filesys_mutex);
  {
    struct file *fp = process_get_file (fd);
    if (fp != NULL)
      f->eax = file_write (fp, buffer, size);
    else
      f->eax = -1;
  }
  lock_release (&filesys_mutex);
}

static void
sys_seek (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  unsigned position = (unsigned)get_user_int (++p);
  lock_acquire (&filesys_mutex);
  {
    struct file *fp = process_get_file (fd);
    if (fp != NULL)
      file_seek (fp, position);
  }
  lock_release (&filesys_mutex);
}

static void
sys_tell (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  lock_acquire (&filesys_mutex);
  {
    struct file *fp = process_get_file (fd);
    if (fp != NULL)
      f->eax = file_tell (fp);
  }
  lock_release (&filesys_mutex);
}

static void
sys_close (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  lock_acquire (&filesys_mutex);
  {
    struct file *fp = process_get_file (fd);
    struct dir *dp = process_get_dir (fd);
    if (fp != NULL)
      {
        file_close (fp);
        process_free_fd (fd);
      }
    else if (dp != NULL)
      {
        dir_close (dp);
        process_free_fd (fd);
      }
  }
  lock_release (&filesys_mutex);
}

static void
sys_chdir (struct intr_frame *f)
{
  int *p = f->esp;
  const char *path = (const char *)get_user_int (++p);
  check_user_string (path);
  lock_acquire (&filesys_mutex);
  {
    struct dir *current_dir = thread_current ()->cd;
    struct dir *dir = NULL;
    bool success = false;
    if (dir_resolve (current_dir, path, &dir, NULL))
      {
        dir_close (current_dir);
        thread_current ()->cd = dir;
        success = true;
      }
    f->eax = success;
  }
  lock_release (&filesys_mutex);
}

static void
sys_mkdir (struct intr_frame *f)
{
  int *p = f->esp;
  const char *path = (const char *)get_user_int (++p);
  check_user_string (path);
  lock_acquire (&filesys_mutex);
  {
    f->eax = filesys_mkdir (path);
  }
  lock_release (&filesys_mutex);
}

static void
sys_readdir (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  char *name = (char *)get_user_int (++p);
  check_user_buffer (name, READDIR_MAX_LEN + 1, true);
  lock_acquire (&filesys_mutex);
  {
    struct dir *dp = process_get_dir (fd);
    if (dp == NULL)
      f->eax = false;
    else
      f->eax = dir_readdir (dp, name);
  }
  lock_release (&filesys_mutex);
}

static void
sys_isdir (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  lock_acquire (&filesys_mutex);
  {
    struct dir *dp = process_get_dir (fd);
    f->eax = dp != NULL;
  }
  lock_release (&filesys_mutex);
}

static void
sys_inumber (struct intr_frame *f)
{
  int *p = f->esp;
  int fd = get_user_int (++p);
  lock_acquire (&filesys_mutex);
  {
    struct file *fp = process_get_file (fd);
    struct dir *dp = process_get_dir (fd);
    if (fp != NULL)
      f->eax = inode_get_sector (file_get_inode (fp));
    else if (dp != NULL)
      f->eax = inode_get_sector (dir_get_inode (dp));
    else
      f->eax = -1;
  }
  lock_release (&filesys_mutex);
}

static void
syscall_handler (struct intr_frame *f)
{
  int n = get_user_int (f->esp);
  switch (n)
  {
    case SYS_HALT:
      sys_halt (f);
      break;
    case SYS_EXIT:
      sys_exit (f);
      break;
    case SYS_EXEC:
      sys_exec (f);
      break;
    case SYS_WAIT:
      sys_wait (f);
      break;
    case SYS_CREATE:
      sys_create (f);
      break;
    case SYS_REMOVE:
      sys_remove (f);
      break;
    case SYS_OPEN:
      sys_open (f);
      break;
    case SYS_FILESIZE:
      sys_filesize (f);
      break;
    case SYS_READ:
      sys_read (f);
      break;
    case SYS_WRITE:
      sys_write (f);
      break;
    case SYS_SEEK:
      sys_seek (f);
      break;
    case SYS_TELL:
      sys_tell (f);
      break;
    case SYS_CLOSE:
      sys_close (f);
      break;
    case SYS_CHDIR:
      sys_chdir (f);
      break;
    case SYS_MKDIR:
      sys_mkdir (f);
      break;
    case SYS_READDIR:
      sys_readdir (f);
      break;
    case SYS_ISDIR:
      sys_isdir (f);
      break;
    case SYS_INUMBER:
      sys_inumber (f);
      break;
    default:
      printf ("Unknown system call: %d\n", n);
      thread_exit ();
      break;
  }
}

/* Reads a byte at user virtual address ADDR.
   ADDR must be below PHYS_BASE.
   Returns the byte value if successful, otherwise exit thread. */
static uint8_t
get_user_byte (const uint8_t *addr)
{
  int result, fail;
  if ((uintptr_t)addr >= (uintptr_t)PHYS_BASE)
    thread_exit ();
  asm ("movl $1f, %0\n"
       "xor %1, %1\n"
       "movzbl %2, %0\n"
       "1:"
       : "=&a" (result), "=&d" (fail) : "m" (*addr));
  if (fail)
    thread_exit ();
  return result;
}

/* Writes byte VALUE to user address ADDR.
   ADDR must be below PHYS_BASE.
   Exit thread if a segfault occurred. */
static void
put_user_byte (uint8_t *addr, uint8_t value)
{
  int fail;
  if ((uintptr_t)addr >= (uintptr_t)PHYS_BASE)
    thread_exit ();
  asm ("movl $1f, %%eax\n"
       "xor %0, %0\n"
       "movb %2, %1\n"
       "1:"
       : "=&d" (fail), "=m" (*addr) : "r" (value) : "eax");
  if (fail)
    thread_exit ();
}

/* Reads a int at user virtual address ADDR.
   ADDR + 3 must be below PHYS_BASE.
   Returns the int value if successful, otherwise exit thread. */
static int
get_user_int (const int *addr)
{
  int result, fail;
  if ((uintptr_t)addr >= (uintptr_t)PHYS_BASE
      || (uintptr_t)addr + 3 >= (uintptr_t)PHYS_BASE)
    thread_exit ();
  asm ("movl $1f, %0\n"
       "xor %1, %1\n"
       "movl %2, %0\n"
       "1:"
       : "=&a" (result), "=&d" (fail) : "m" (*addr));
  if (fail)
    thread_exit ();
  return result;
}

/* Writes int VALUE to user address ADDR.
   ADDR + 3 must be below PHYS_BASE.
   Exit thread if a segfault occurred. */
static void
put_user_int (int *addr, int value)
{
  int fail;
  if ((uintptr_t)addr >= (uintptr_t)PHYS_BASE
      || (uintptr_t)addr + 3 >= (uintptr_t)PHYS_BASE)
    thread_exit ();
  asm ("movl $1f, %%eax\n"
       "xor %0, %0\n"
       "movl %2, %1\n"
       "1:"
       : "=&d" (fail), "=m" (*addr) : "r" (value) : "eax");
  if (fail)
    thread_exit ();
}

/* Check the string at user address is accessible. */
static void
check_user_string (const char *str)
{
  while (get_user_byte ((const uint8_t *)str) != '\0')
    str++;
}

/* Check the buffer with size at user address is accessible. */
static void
check_user_buffer (const void *buffer, size_t size, bool writable)
{
  size_t i;
  uint8_t b;
  if (size == 0)
    return;
  for (i = 0; i < size; i += PGSIZE)
    {
      b = get_user_byte ((const uint8_t *)buffer + i);
      if (writable)
        put_user_byte ((uint8_t *)buffer + i, b);
    }
  b = get_user_byte ((const uint8_t *)buffer + (size - 1));
  if (writable)
    put_user_byte ((uint8_t *)buffer + (size - 1), b);
}
