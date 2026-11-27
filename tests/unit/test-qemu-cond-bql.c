/*
 * Regression tests for the OPT_BQL condition-variable wait protocol.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/thread.h"
#include "test-qemu-cond-bql.h"
#include <sys/syscall.h>

typedef enum WaitKind {
    WAIT_SPIN,
    WAIT_FUTEX,
    WAIT_SPIN_FUTEX,
    WAIT_GENERATION,
} WaitKind;

typedef struct WaitRace {
    QemuMutex mutex;
    QemuCond cond;
    QemuSemaphore unlocked;
    QemuSemaphore resume;
    WaitKind kind;
    bool pending;
    unsigned completed;
} WaitRace;

static __thread WaitRace *unlock_race;

typedef struct SignalWaiter {
    QemuMutex *mutex;
    QemuCond *cond;
    QemuSemaphore unlocked;
    QemuSemaphore resume;
    long tid;
    unsigned completed;
} SignalWaiter;

static __thread SignalWaiter *signal_waiter;

/*
 * Pause each waiter after releasing the predicate lock, before returning to
 * the real wait function. The broadcaster runs only after both waiters have
 * unlocked. This reproduces a wake racing with late ticket registration
 * without adding hooks or replacing the production condition-variable code.
 */
int __wrap_pthread_spin_unlock(pthread_spinlock_t *spin)
{
    WaitRace *race = unlock_race;
    int ret = __real_pthread_spin_unlock(spin);

    if (race && spin == &race->mutex.spin) {
        unlock_race = NULL;
        qemu_sem_post(&race->unlocked);
        qemu_sem_wait(&race->resume);
    }
    if (signal_waiter && spin == &signal_waiter->mutex->spin) {
        SignalWaiter *waiter = signal_waiter;

        signal_waiter = NULL;
        qemu_sem_post(&waiter->unlocked);
        qemu_sem_wait(&waiter->resume);
    }
    return ret;
}

static void wake_waiters(WaitRace *race)
{
    if (race->kind == WAIT_SPIN) {
        qemu_cond_broadcast_1(&race->cond);
    } else if (race->kind == WAIT_GENERATION) {
        qemu_cond_broadcast_2(&race->cond);
    } else {
        qemu_cond_broadcast_3(&race->cond);
    }
}

static void *race_waiter(void *opaque)
{
    WaitRace *race = opaque;

    qemu_mutex_lock_1(&race->mutex);
    unlock_race = race;
    while (race->pending) {
        if (race->kind == WAIT_SPIN) {
            qemu_cond_wait_1(&race->cond, &race->mutex);
        } else if (race->kind == WAIT_GENERATION) {
            qemu_cond_wait_2(&race->cond, &race->mutex);
        } else {
            int spins = race->kind == WAIT_FUTEX ? 0 : 1024;

            qemu_cond_wait_3(&race->cond, &race->mutex, spins);
        }
    }
    unlock_race = NULL;
    qemu_mutex_unlock_1(&race->mutex);
    qatomic_inc(&race->completed);
    return NULL;
}

static void test_broadcast_after_unlock(gconstpointer opaque)
{
    WaitRace race = { .pending = true, .kind = GPOINTER_TO_INT(opaque) };
    QemuThread threads[2];
    unsigned completed;
    int64_t deadline;
    int i;

    qemu_mutex_init(&race.mutex);
    qemu_cond_init(&race.cond);
    qemu_sem_init(&race.unlocked, 0);
    qemu_sem_init(&race.resume, 0);
    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        qemu_thread_create(&threads[i], "cond-waiter", race_waiter, &race,
                           QEMU_THREAD_JOINABLE);
    }

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        qemu_sem_wait(&race.unlocked);
    }
    qemu_mutex_lock_1(&race.mutex);
    race.pending = false;
    wake_waiters(&race);
    qemu_mutex_unlock_1(&race.mutex);
    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        qemu_sem_post(&race.resume);
    }

    deadline = g_get_monotonic_time() + G_TIME_SPAN_SECOND;
    while (qatomic_read(&race.completed) != ARRAY_SIZE(threads) &&
           g_get_monotonic_time() < deadline) {
        g_usleep(100);
    }
    completed = qatomic_read(&race.completed);

    /* A failing implementation must not leave a test worker spinning. */
    qemu_mutex_lock_1(&race.mutex);
    wake_waiters(&race);
    qemu_mutex_unlock_1(&race.mutex);
    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        qemu_thread_join(&threads[i]);
    }
    qemu_sem_destroy(&race.resume);
    qemu_sem_destroy(&race.unlocked);
    qemu_cond_destroy(&race.cond);
    pthread_spin_destroy(&race.mutex.spin);
    qemu_mutex_destroy(&race.mutex);

    g_assert_cmpuint(completed, ==, ARRAY_SIZE(threads));
}

typedef struct NotifyRace {
    QemuMutex mutex;
    QemuCond cond;
    QemuEvent start;
    unsigned done;
} NotifyRace;

static void *reserve_tickets(void *opaque)
{
    NotifyRace *race = opaque;
    unsigned i;

    qemu_event_wait(&race->start);
    for (i = 0; i < 1000000; i++) {
        qemu_mutex_lock_1(&race->mutex);
        qemu_cond_wait_prepare_1(&race->cond);
        qemu_mutex_unlock_1(&race->mutex);
    }
    qatomic_inc(&race->done);
    return NULL;
}

static void *broadcast_tickets(void *opaque)
{
    NotifyRace *race = opaque;
    unsigned i;

    qemu_event_wait(&race->start);
    for (i = 0; i < 1000000; i++) {
        qemu_cond_broadcast_1(&race->cond);
    }
    qatomic_inc(&race->done);
    return NULL;
}

static void test_concurrent_broadcasts(void)
{
    NotifyRace race = {};
    QemuThread threads[3];
    unsigned long previous = 0;
    unsigned regressions = 0;
    int i;

    qemu_mutex_init(&race.mutex);
    qemu_cond_init(&race.cond);
    qemu_event_init(&race.start, false);
    qemu_thread_create(&threads[0], "cond-reserve", reserve_tickets, &race,
                       QEMU_THREAD_JOINABLE);
    for (i = 1; i < ARRAY_SIZE(threads); i++) {
        qemu_thread_create(&threads[i], "cond-notify", broadcast_tickets, &race,
                           QEMU_THREAD_JOINABLE);
    }
    qemu_event_set(&race.start);
    while (qatomic_read(&race.done) != ARRAY_SIZE(threads)) {
        unsigned long released = qatomic_read(&race.cond.release_seq);

        if (released < previous) {
            regressions++;
        }
        previous = released;
    }
    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        qemu_thread_join(&threads[i]);
    }
    qemu_event_destroy(&race.start);
    qemu_cond_destroy(&race.cond);
    pthread_spin_destroy(&race.mutex.spin);
    qemu_mutex_destroy(&race.mutex);

    g_assert_cmpuint(regressions, ==, 0);
}

static void test_bounded_poll_ticket(void)
{
    QemuMutex mutex;
    QemuCond cond;
    unsigned long first, second, third;

    qemu_mutex_init(&mutex);
    qemu_cond_init(&cond);
    qemu_mutex_lock_1(&mutex);
    first = qemu_cond_wait_prepare_1(&cond);
    second = qemu_cond_wait_prepare_1(&cond);
    qemu_mutex_unlock_1(&mutex);

    /* The second waiter timing out must not replace its reserved ticket. */
    g_assert_false(qemu_cond_wait_1_n_unlocked(&cond, second, 16));
    qemu_cond_signal_1(&cond);
    g_assert_true(qemu_cond_wait_1_n_unlocked(&cond, first, 16));
    g_assert_false(qemu_cond_wait_1_n_unlocked(&cond, second, 16));

    qemu_mutex_lock_1(&mutex);
    third = qemu_cond_wait_prepare_1(&cond);
    qemu_cond_signal_1(&cond);
    qemu_mutex_unlock_1(&mutex);
    g_assert_true(qemu_cond_wait_1_n_unlocked(&cond, second, 16));
    g_assert_false(qemu_cond_wait_1_n_unlocked(&cond, third, 16));

    qemu_cond_broadcast_1(&cond);
    g_assert_true(qemu_cond_wait_1_n_unlocked(&cond, third, 16));
    qemu_cond_destroy(&cond);
    pthread_spin_destroy(&mutex.spin);
    qemu_mutex_destroy(&mutex);
}

static void test_kick_before_registration(void)
{
    QemuMutex mutex;
    QemuCond cond;
    unsigned long ticket;

    qemu_mutex_init(&mutex);
    qemu_cond_init(&cond);

    /* A vCPU kick can race with the idle check without holding the BQL. */
    qemu_cond_broadcast_3(&cond);
    qemu_mutex_lock_1(&mutex);
    ticket = qemu_cond_wait_prepare_1(&cond);
    qemu_mutex_unlock_1(&mutex);
    g_assert_true(qemu_cond_wait_1_n_unlocked(&cond, ticket, 16));

    qemu_cond_destroy(&cond);
    pthread_spin_destroy(&mutex.spin);
    qemu_mutex_destroy(&mutex);
}

static void test_timedwait_timeout(void)
{
    QemuMutex mutex;
    QemuCond cond;
    int64_t start, elapsed;

    qemu_mutex_init(&mutex);
    qemu_cond_init(&cond);
    qemu_mutex_lock_1(&mutex);

    start = g_get_monotonic_time();
    qemu_cond_timedwait_1(&cond, &mutex, 20);
    elapsed = g_get_monotonic_time() - start;

    /* The timeout path must return with the predicate lock re-acquired. */
    qemu_mutex_unlock_1(&mutex);
    g_assert_cmpint(elapsed, >=, 10 * G_TIME_SPAN_MILLISECOND);
    g_assert_cmpint(elapsed, <, G_TIME_SPAN_SECOND);

    qemu_cond_destroy(&cond);
    pthread_spin_destroy(&mutex.spin);
    qemu_mutex_destroy(&mutex);
}

typedef struct TimedWaiter {
    QemuCond *cond;
} TimedWaiter;

static void *timedwait_waker(void *opaque)
{
    TimedWaiter *waiter = opaque;

    g_usleep(50 * G_TIME_SPAN_MILLISECOND);
    qemu_cond_broadcast_3(waiter->cond);
    return NULL;
}

static void test_timedwait_signal(void)
{
    QemuMutex mutex;
    QemuCond cond;
    TimedWaiter waiter = { .cond = &cond };
    QemuThread thread;
    int64_t start, elapsed;

    qemu_mutex_init(&mutex);
    qemu_cond_init(&cond);
    qemu_thread_create(&thread, "timedwait-waker", timedwait_waker, &waiter,
                       QEMU_THREAD_JOINABLE);

    qemu_mutex_lock_1(&mutex);
    start = g_get_monotonic_time();
    qemu_cond_timedwait_1(&cond, &mutex, 5000);
    elapsed = g_get_monotonic_time() - start;
    qemu_mutex_unlock_1(&mutex);

    qemu_thread_join(&thread);
    g_assert_cmpint(elapsed, <, 4 * G_TIME_SPAN_SECOND);

    qemu_cond_destroy(&cond);
    pthread_spin_destroy(&mutex.spin);
    qemu_mutex_destroy(&mutex);
}

static void *signal_race_waiter(void *opaque)
{
    SignalWaiter *waiter = opaque;

    qatomic_set(&waiter->tid, syscall(SYS_gettid));
    qemu_mutex_lock_1(waiter->mutex);
    signal_waiter = waiter;
    qemu_cond_wait_3(waiter->cond, waiter->mutex, 0);
    qemu_mutex_unlock_1(waiter->mutex);
    qatomic_set(&waiter->completed, 1);
    return NULL;
}

/* Confirm the actual futex queue order, rather than relying on sleeps. */
static bool waiter_in_futex(SignalWaiter *waiter)
{
    g_autofree char *path = g_strdup_printf("/proc/self/task/%ld/syscall",
                                           qatomic_read(&waiter->tid));
    int64_t deadline = g_get_monotonic_time() + G_TIME_SPAN_SECOND;

    while (g_get_monotonic_time() < deadline) {
        g_autofree char *state = NULL;
        long number;
        unsigned long address;

        if (!g_file_get_contents(path, &state, NULL, NULL)) {
            return false;
        }
        if (sscanf(state, "%ld %lx", &number, &address) == 2 &&
            number == SYS_futex &&
            address == (uintptr_t)&waiter->cond->futex_seq) {
            return true;
        }
        g_usleep(100);
    }
    return false;
}

static void test_signal_futex_queue_order(void)
{
    QemuMutex mutex;
    QemuCond cond;
    SignalWaiter waiters[2] = {};
    QemuThread threads[2];
    bool queued[2];
    unsigned completed;
    int64_t deadline;
    int i;

    qemu_mutex_init(&mutex);
    qemu_cond_init(&cond);
    for (i = 0; i < ARRAY_SIZE(waiters); i++) {
        waiters[i].mutex = &mutex;
        waiters[i].cond = &cond;
        qemu_sem_init(&waiters[i].unlocked, 0);
        qemu_sem_init(&waiters[i].resume, 0);
        qemu_thread_create(&threads[i], "cond-signal", signal_race_waiter,
                           &waiters[i], QEMU_THREAD_JOINABLE);
        qemu_sem_wait(&waiters[i].unlocked);
    }

    /* The second ticket enters the kernel queue before the first ticket. */
    qemu_sem_post(&waiters[1].resume);
    queued[1] = waiter_in_futex(&waiters[1]);
    qemu_sem_post(&waiters[0].resume);
    queued[0] = waiter_in_futex(&waiters[0]);
    qemu_mutex_lock_1(&mutex);
    qemu_cond_signal_3(&cond);
    qemu_mutex_unlock_1(&mutex);
    deadline = g_get_monotonic_time() + G_TIME_SPAN_SECOND;
    while (!qatomic_read(&waiters[0].completed) &&
           g_get_monotonic_time() < deadline) {
        g_usleep(100);
    }
    completed = qatomic_read(&waiters[0].completed);

    qemu_cond_broadcast_3(&cond);
    for (i = 0; i < ARRAY_SIZE(waiters); i++) {
        qemu_thread_join(&threads[i]);
        qemu_sem_destroy(&waiters[i].resume);
        qemu_sem_destroy(&waiters[i].unlocked);
    }
    qemu_cond_destroy(&cond);
    pthread_spin_destroy(&mutex.spin);
    qemu_mutex_destroy(&mutex);

    if (!queued[0] || !queued[1]) {
        g_test_skip("Cannot inspect futex queues through /proc/self/task");
    } else {
        g_assert_cmpuint(completed, ==, 1);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_data_func("/qemu-cond-bql/wait1/broadcast-after-unlock",
                         GINT_TO_POINTER(WAIT_SPIN),
                         test_broadcast_after_unlock);
    g_test_add_data_func("/qemu-cond-bql/wait3/futex/broadcast-after-unlock",
                         GINT_TO_POINTER(WAIT_FUTEX),
                         test_broadcast_after_unlock);
    g_test_add_data_func(
        "/qemu-cond-bql/wait3/spin-futex/broadcast-after-unlock",
        GINT_TO_POINTER(WAIT_SPIN_FUTEX), test_broadcast_after_unlock);
    g_test_add_func("/qemu-cond-bql/notify/concurrent-broadcasts",
                    test_concurrent_broadcasts);
    g_test_add_data_func("/qemu-cond-bql/wait2/broadcast-after-unlock",
                         GINT_TO_POINTER(WAIT_GENERATION),
                         test_broadcast_after_unlock);
    g_test_add_func("/qemu-cond-bql/bounded-poll/stable-ticket",
                    test_bounded_poll_ticket);
    g_test_add_func("/qemu-cond-bql/notify/kick-before-registration",
                    test_kick_before_registration);
    g_test_add_func("/qemu-cond-bql/timedwait/timeout",
                    test_timedwait_timeout);
    g_test_add_func("/qemu-cond-bql/timedwait/signal",
                    test_timedwait_signal);
    g_test_add_func("/qemu-cond-bql/wait3/signal-futex-queue-order",
                    test_signal_futex_queue_order);
    return g_test_run();
}
