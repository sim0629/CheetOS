#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static struct list all_list;
static struct lock list_mutex;

static thread_func start_process NO_RETURN;
static bool load (char *args_page, void (**eip) (void), void **esp);
static void parse_args (char *cmdline_page, char *args_page);
static struct process *get_proc_from_id (pid_t pid);
static void make_children_orphan (pid_t pid);
static void reap_proc (struct process *proc);

void
process_init ()
{
  ASSERT (intr_get_level () == INTR_OFF);
  list_init (&all_list);
  lock_init (&list_mutex);
}

/* Starts a new thread running a user program loaded from
   CMDLINE.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline)
{
  char *cmdline_page, *args_page;
  const char *file_name;
  tid_t tid;
  char *pcb;
  struct process *proc;

  cmdline_page = palloc_get_page (0);
  if (cmdline_page == NULL)
    return TID_ERROR;

  args_page = palloc_get_page (0);
  if (args_page == NULL)
    {
      palloc_free_page (cmdline_page);
      return TID_ERROR;
    }

  pcb = palloc_get_page (0);
  if (pcb == NULL)
    {
      palloc_free_page (args_page);
      palloc_free_page (cmdline_page);
      return TID_ERROR;
    }

  strlcpy (cmdline_page, cmdline, PGSIZE);
  parse_args (cmdline_page, args_page);
  file_name = cmdline_page;

  proc = (struct process *)pcb;
  proc->pid = TID_ERROR; // will be filled at thread_create_process
  proc->ppid = thread_tid ();
  proc->exit_code = -1;
  memset (proc->files, 0, sizeof (proc->files));
  lock_init (&proc->fd_mutex);
  sema_init (&proc->listed, 0);
  sema_init (&proc->exited, 0);

  /* Create a new thread to execute FILE_NAME with ARGS_PAGE. */
  tid = thread_create_process (file_name, PRI_DEFAULT, start_process,
                               args_page, proc);
  if (tid == TID_ERROR)
    {
      palloc_free_page (pcb);
      palloc_free_page (args_page);
    }
  else
    {
      lock_acquire (&list_mutex);
      list_push_back (&all_list, &proc->allelem);
      lock_release (&list_mutex);
      sema_up (&proc->listed);
    }

  palloc_free_page (cmdline_page);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_page_)
{
  char *args_page = args_page_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args_page, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (args_page);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid)
{
  int status = -1;
  struct process *child_proc = get_proc_from_id (child_tid);
  if (child_proc == NULL || child_proc->ppid != thread_tid ())
    return status;

  sema_down (&child_proc->exited);

  status = child_proc->exit_code;
  reap_proc (child_proc);
  return status;
}

/* Exit current process. */
void
process_exit (int status)
{
  struct process *proc = thread_current ()->proc;
  if (proc != NULL)
    proc->exit_code = status;
  thread_exit ();
}

/* Free the current process's resources. */
void
process_thread_exit ()
{
  struct thread *cur = thread_current ();
  struct process *proc = cur->proc;
  uint32_t *pd;

  if (proc != NULL)
    {
      cur->proc = NULL;
      printf ("%s: exit(%d)\n", cur->name, proc->exit_code);
      make_children_orphan (proc->pid);
      if (proc->ppid == TID_ERROR)
        reap_proc (proc);
      else
        sema_up (&proc->exited);
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *args_page);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from ARGS_PAGE into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (char *args_page, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  const char *file_name = *(const char **)(args_page + sizeof (size_t));

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, args_page))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *args_page)
{
  uint8_t *kpage;
  char *stack;
  size_t argc, i, arg_len;
  char *arg;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage == NULL)
    return false;

  if (!install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true))
    {
      palloc_free_page (kpage);
      return false;
    }

  *esp = PHYS_BASE;
  stack = (char *)(*esp);
  argc = *(size_t *)args_page;

  for (i = argc; i > 0; i--)
    {
      uintptr_t arg_ptr = (uintptr_t)args_page +
                          sizeof (size_t) +
                          (i - 1) * sizeof (char *);
      arg = *(char **)arg_ptr;
      arg_len = strlen (arg);
      stack -= arg_len + 1; strlcpy (stack, arg, arg_len + 1);
      *(char **)arg_ptr = stack;
    }

  /* Word-align */
  stack = (char *)((uintptr_t)stack & ~(uintptr_t)(4 - 1));

  stack -= sizeof (char *); *(char **)stack = NULL;

  for (i = argc; i > 0; i--)
    {
      uintptr_t arg_ptr = (uintptr_t)args_page +
                          sizeof (size_t) +
                          (i - 1) * sizeof (char *);
      stack -= sizeof (char *); *(char **)stack = *(char **)arg_ptr;
    }

  stack -= sizeof (char *); *(char **)stack = stack + sizeof (char *);
  stack -= sizeof (size_t); *(size_t *)stack = argc;
  stack -= sizeof (void *); *(void **)stack = NULL;
  *esp = stack;
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Construct ARGS_PAGE with CMDLINE_PAGE.
   Layout of ARGS_PAGE is shown below.
   | argc         |
   | argv[0]      |
   | argv[1]      |
   | ...          |
   | argv[0][...] |
   | argv[1][...] | */
static void
parse_args (char *cmdline_page, char *args_page)
{
  const char *delim = " ";
  char *ctx;
  const char *token;
  size_t token_len;
  size_t argc = 0, i;
  unsigned offset = sizeof (size_t); /* 0 for ARGC */

  token = strtok_r (cmdline_page, delim, &ctx);
  while (token != NULL)
    {
      *(const char **)(args_page + offset) = token;
      offset += sizeof (const char *);
      argc++;
      token = strtok_r (NULL, delim, &ctx);
    }

  *(size_t *)args_page = argc;
  for (i = 0; i < argc; i++)
    {
      uintptr_t arg_ptr = (uintptr_t)args_page +
                          sizeof (size_t) +
                          i * sizeof (const char *);
      token = *(const char **)arg_ptr;
      token_len = strlen (token);
      strlcpy (args_page + offset, token, token_len + 1);
      *(const char **)arg_ptr = args_page + offset;
      offset += token_len + 1;
    }
}

static struct process *
get_proc_from_id (pid_t pid)
{
  struct process *proc = NULL;
  lock_acquire (&list_mutex);
  {
    struct list_elem *e = list_begin (&all_list);
    struct list_elem *f = list_end (&all_list);
    for (; e != f; e = list_next (e))
      {
        struct process *p = list_entry (e, struct process, allelem);
        if (p->pid == pid)
          {
            proc = p;
            break;
          }
      }
  }
  lock_release (&list_mutex);
  return proc;
}

static void
make_children_orphan (pid_t pid)
{
  lock_acquire (&list_mutex);
  {
    struct list_elem *e = list_begin (&all_list);
    struct list_elem *f = list_end (&all_list);
    for (; e != f; e = list_next (e))
      {
        struct process *p = list_entry (e, struct process, allelem);
        if (p->ppid == pid)
          p->ppid = TID_ERROR;
      }
  }
  lock_release (&list_mutex);
}

static void
reap_proc (struct process *proc)
{
  sema_down (&proc->listed);

  lock_acquire (&list_mutex);
  list_remove (&proc->allelem);
  lock_release (&list_mutex);
  palloc_free_page (proc);
}

/* Allocates a file descriptor to file FP and returns the fd.
   Returns FD_ERROR if exceed the limit number MAX_FD. */
int
process_alloc_fd (struct file *fp)
{
  struct process *proc = thread_current ()->proc;
  int fd = FD_ERROR, i;
  if (fp == NULL)
    return fd;
  lock_acquire (&proc->fd_mutex);
  for (i = 0; i < MAX_FD; i++)
    {
      if (proc->files[i] == NULL)
        {
          proc->files[i] = fp;
          fd = i + RESERVED_FD;
          break;
        }
    }
  lock_release (&proc->fd_mutex);
  return fd;
}

/* Returns the open file associated with FD. */
struct file *
process_get_file (int fd)
{
  struct process *proc = thread_current ()->proc;
  struct file *fp;
  int i = fd - RESERVED_FD;
  if (i < 0 || i >= MAX_FD)
    return NULL;
  lock_acquire (&proc->fd_mutex);
  fp = proc->files[i];
  lock_release (&proc->fd_mutex);
  return fp;
}

/* Remove the FD from file descriptor table. */
void
process_free_fd (int fd)
{
  struct process *proc = thread_current ()->proc;
  int i = fd - RESERVED_FD;
  if (i < 0 || i >= MAX_FD)
    return;
  lock_acquire (&proc->fd_mutex);
  proc->files[i] = NULL;
  lock_release (&proc->fd_mutex);
}
