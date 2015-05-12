#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"

#define pid_t tid_t

#define MAX_FD      128  /* The maximum number of open files per a process. */
#define RESERVED_FD   2  /* 0 and 1 are reserved for stdin and stdout. */
#define FD_ERROR   (-1)

struct process
  {
    pid_t pid;                 /* Same as TID of its thread. */
    pid_t ppid;                /* Parent's PID. */
    int exit_code;

    struct file *files[MAX_FD];
    struct lock fd_mutex;

    struct semaphore listed;
    struct semaphore exited;

    /* Owned by process.c */
    struct list_elem allelem;
  };

void process_init (void);
tid_t process_execute (const char *cmdline);
int process_wait (tid_t);
void process_exit (int);
void process_thread_exit (void);
void process_activate (void);

int process_alloc_fd (struct file *);
struct file *process_get_file (int fd);
void process_free_fd (int fd);

#endif /* userprog/process.h */
