#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define pid_t tid_t

tid_t process_execute (const char *cmdline);
int process_wait (tid_t);
void process_exit (int);
void process_thread_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
