#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"

#define pid_t tid_t

struct process
  {
    pid_t pid;                 /* Same as TID of its thread. */
    pid_t ppid;                /* Parent's PID. */
    int exit_code;

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

#endif /* userprog/process.h */
