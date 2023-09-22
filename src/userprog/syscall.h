#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* To be shared with process.c. */
void close_all_thread_fds (void);

#endif /* userprog/syscall.h */
