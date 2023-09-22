#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* To be shared with syscall.c. */
/* Data structure to keep track of important thread information after
   the thread exits. */
struct process_info {
    tid_t tid;                    /* Thread ID. (identity mapping to pid_t) */
    int exit_status;              /* Thread exit status. */
    bool loaded_executable;       /* Successfully loaded executable or not. */
    bool dead;                    /* Thread is currently dead or not. */     
    struct semaphore wait_sema;   /* Semaphore for parent to wait on child. */
    struct semaphore load_sema;   /* Semaphore for parent to wait for child to load. */
    struct list_elem elem;        /* List element for process_info. */
};

void process_info_init (struct process_info *pi, tid_t tid);
struct process_info *process_info_by_tid (struct thread *parent, tid_t tid);

/* Load helper, shared by VM. */
bool install_page (void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
