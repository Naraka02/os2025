#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>
#include "testkit.h"

static struct tk_testcase tests[TK_MAX_TESTS];

/**
 * Add a test case to the test suite. Handles both system tests (calling
 * main with command-line arguments) and unit tests. This is the only
 * externally visible function in TestKit.
 */
void tk_add_test(struct tk_testcase t) {
    static int ntests = 0;

    // Only add the test case when TestKit is enabled.
    if (!getenv(TK_RUN) && !getenv(TK_VERBOSE)) {
        return;
    }

    tk_assert(ntests < TK_MAX_TESTS,
              "TestKit supports up to %d test cases", TK_MAX_TESTS);

    tests[ntests] = t;

    if (t.argv) {
        // This is a system test that calls main().
        tk_assert(t.stest, "Only system tests can have argv");

        // Test cases specify args via in-place arrays like:
        //   (char *[]){"first argument", "second argument"})
        // whose space is stack-allocated. Allocate space and copy.

        // Make space for argv[0] and trailing NULL.
        struct tk_testcase *cur = &tests[ntests];
        cur->argc++;
        cur->argv_copy[cur->argc] = NULL;
        cur->argv_copy[0] = getenv("_");

        tk_assert(cur->argv_copy[0] != NULL,
                  "TestKit requires shell put executable in environ; "
                  "try run with bash");

        for (int i = 1; i < cur->argc; i++) {
            // String literals are compile-time constants; we are safe to
            // do only a shallow copy.
            cur->argv_copy[i] = t.argv[i - 1];
        }

        // This is important (and tricky): there is a cross-process
        // "memcpy" of tests to the worker after main(). We must make
        // sure there is no dangling pointers.
        cur->argv = cur->argv_copy;
    }

    ntests++;
}

// ------------------------------------------------------------------------
// Below are testkit internal functions for running test cases.

static int run_testcase(struct tk_testcase *t, char *buf) {
    int r = 0;

    if (t->init) {
        // Run test setup
        t->init();
    }

    // Redirect both stdout and stderr to a memory buffer. This only
    // affects calls to printf() and fprintf() to stdout and stderr.
    // Writes to file descriptors will not be captured, nor will writes
    // to redirected file descriptors.

    FILE *fp = fmemopen(buf, TK_OUTPUT_LIMIT - 1, "w+");
    tk_assert(fp, "fmemopen() should succeed");
    setbuf(fp, NULL);
    stdout = stderr = fp;

    if (t->stest) {
        // Run system test: call main() manually
        int main(int, const char **, const char **);
        extern const char **environ;

        pid_t child_pid = fork();
        if (child_pid == 0) {
            exit(main(t->argc, t->argv, environ));
        } else {
            int status;
            waitpid(child_pid, &status, 0);
            if (WIFEXITED(status)) {
                r = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                // main() is terminated by a signal;
                // kill myself :)
                kill(getpid(), WTERMSIG(status));
            }

            // Runt the bottom-half (test code).
            t->stest(&(struct tk_result) {
                .exit_status = r,
                .output = buf,
            });
        }
    } else {
        // Run unit test: just run the test code.
        t->utest();
    }

    fclose(fp);
    return r;
}

static void run_cleanup(struct tk_testcase *t) {
    if (t->fini) {
        pid_t fini_pid = fork();
        if (fini_pid == 0) {
            // Cleanup function may also timeout.
            alarm(TK_TIME_LIMIT_SEC);
            t->fini();
            exit(0);
        } else {
            waitpid(fini_pid, NULL, 0);
        }
    }
}

static char *pcol(const char *s, int color) {
    // This is a single-threaded one-call per expression hack.
    static char buf[64];

    if (isatty(STDOUT_FILENO)) {
        snprintf(buf, sizeof(buf), "\033[0;%dm%s\033[0;0m", color, s);
    } else {
        snprintf(buf, sizeof(buf), "%s", s);
    }

    return buf;
}

static bool check_results(struct tk_testcase *t, int status) {
    // Print test result according to process exit status.
    bool succ = false;

    if (WIFEXITED(status)) {
        // Normal exit.
        succ = true;
        printf("- [%s] %s (%s)\n", pcol("PASS", 32), t->name, t->loc);
    } else {
        // Killed/stopped by a signal.
        printf("- [%s] %s (%s)", pcol("FAIL", 31), t->name, t->loc);
        const char *msg = pcol("unknown error", 31);

        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            switch (sig) {
                case SIGALRM: msg = pcol("Timeout", 33); break;
                case SIGABRT: msg = pcol("Assertion fail", 35); break;
                case SIGSEGV: msg = pcol("Segmentation fault", 36); break;
                default: msg = pcol(strsignal(sig), 31);
            }
        }
        printf(" - %s\n", msg);
    }

    return succ;
}

static void run_all_testcases(void) {
    if (!tests[0].enabled) {
        // Don't bother non-testing runs.
        return;
    }

    // There are test cases only if there's TK_RUN or TK_VERBOSE.
    bool verbose = getenv(TK_VERBOSE) != NULL;

    // Creating subprocesses may cause multiple atexit flushes to the stdio
    // buffers. Clean them immediately and set stdout to non-buffered mode.
    fflush(stdout);
    fflush(stderr);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("\nTestKit\n");

    int passed = 0, ntests = 0;

    for (int i = 0; tests[i].enabled; i++, ntests++) {
        struct tk_testcase *t = &tests[i];

        char *buf = mmap(NULL,
            TK_OUTPUT_LIMIT,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        tk_assert(buf != MAP_FAILED, "mmap() should succeed");

        // Run test case in a separated process.
        pid_t pid = fork();
        if (pid == 0) {
            // Child: run test case for TIME_LIMIT.
            alarm(TK_TIME_LIMIT_SEC);
            exit(run_testcase(t, buf));
        } else {
            // Parent: wait for child and run t->fini().
            int status;
            waitpid(pid, &status, 0);

            if (check_results(t, status)) {
                passed++;
            } else if (verbose) {
                printf(pcol("%s", 90), buf);
                if (!buf[0] || buf[strlen(buf) - 1] != '\n') {
                    printf("\n");
                }
            }

            // Cleanup code is also ran in a separate process.
            run_cleanup(t);
        }

        munmap(buf, TK_OUTPUT_LIMIT);
    }

    printf("- %d/%d test cases passed.\n", passed, ntests);
}

static int worker_pid;
static int pipe_read, pipe_write;

static void notify_worker() {
    // Signal the worker process--we must send tests array because
    // tests in the worker process may not be correctly initialized.

    write(pipe_write, tests, sizeof(tests));
    close(pipe_write);

    // Wait for the worker to complete
    waitpid(worker_pid, NULL, 0);
}

static void worker_process() {
    // tk_register_hook() creates a forked process to run this.
    // Read the tests array from the pipe and run all test cases.

    ssize_t bytes_read;

    for (bytes_read = 0; bytes_read < sizeof(tests); ) {
        ssize_t result = read(pipe_read,
            (char *)tests + bytes_read,
            sizeof(tests) - bytes_read
        );
        if (result <= 0) break; // Error or EOF
        bytes_read += result;
    }

    close(pipe_read);

    run_all_testcases();
    exit(0);
}

__attribute__((constructor))
void tk_register_hook(void) {
    // This is tricky: we must not call run_all_testcases() at exit; otherwise
    // the exit() in atexit causes undefined behavior).

    // Create a pipe for synchronization
    int fds[2];
    if (pipe(fds) == -1) {
        perror("pipe");
        return;
    }
    pipe_read = fds[0];
    pipe_write = fds[1];

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipe_write);
        worker_process();
    } else {
        // Parent process
        worker_pid = pid;
        close(pipe_read);
        atexit(notify_worker);
    }
}
