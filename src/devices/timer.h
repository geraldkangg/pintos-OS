#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
#include <list.h>

/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

/* Wrapper struct for timer sleeping. */
struct timed_thread
{
  struct thread *t;         /* Sleeping thread. */
  uint32_t wake_tick;       /* Tick to wake on. */
  struct list_elem elem;    /* Sleeping thread list element. */
};

void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

/* Sleep and yield the CPU to other threads. */
void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

/* Busy waits. */
void timer_mdelay (int64_t milliseconds);
void timer_udelay (int64_t microseconds);
void timer_ndelay (int64_t nanoseconds);

void timer_print_stats (void);

/* Comparison function for sleeping thread list. */
bool cmp_thread_wake (const struct list_elem *, const struct list_elem *,
                 void * UNUSED);

#endif /* devices/timer.h */
