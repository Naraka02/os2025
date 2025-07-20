#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

#define MAX_SYSCALLS 1000
#define BUFFER_SIZE 4096

typedef struct {
    char name[64];
    double total_time;
} SyscallTime;

SyscallTime syscalls[MAX_SYSCALLS];
size_t num_syscalls = 0;

void update_stat(const char *name, double time) {
    for (size_t i = 0; i < num_syscalls; i++) {
        if (strcmp(syscalls[i].name, name) == 0) {
            syscalls[i].total_time += time;
            return;
        }
    }
    if (num_syscalls < MAX_SYSCALLS) {
        strncpy(syscalls[num_syscalls].name, name, sizeof(syscalls[num_syscalls].name));
        syscalls[num_syscalls].name[sizeof(syscalls[num_syscalls].name) - 1] = '\0';
        syscalls[num_syscalls].total_time = time;
        num_syscalls++;
    }
}

int compare_syscall_time(const void *a, const void *b) {
    const SyscallTime *sa = (const SyscallTime *)a;
    const SyscallTime *sb = (const SyscallTime *)b;
    if (sa->total_time > sb->total_time) return -1;
    if (sa->total_time < sb->total_time) return 1;
    return 0;
}

void print_top5() {
    double total = 0;
    for (size_t i = 0; i < num_syscalls; i++) {
        total += syscalls[i].total_time;
    }
    if (total == 0) return;

    SyscallTime sorted[MAX_SYSCALLS];
    memcpy(sorted, syscalls, sizeof(SyscallTime) * num_syscalls);
    qsort(sorted, num_syscalls, sizeof(SyscallTime), compare_syscall_time);

    int count = 0;
    printf("Time: %f seconds\n", total);
    for (size_t i = 0; i < num_syscalls && count < 5; i++) {
        int ratio = (int)((sorted[i].total_time / total) * 100);
        printf("%s (%d%%)\n", sorted[i].name, ratio);
        count++;
    }

    char zeros[80] = {0};
    fwrite(zeros, 1, sizeof(zeros), stdout);
    fflush(stdout);
}

void process_line(const char *line) {
    const char *lt = strrchr(line, '<');
    if (!lt) return;
    const char *gt = strrchr(lt, '>');
    if (!gt) return;

    if (*(gt + 1) != '\0') {
        const char *p = gt + 1;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (*p) return;
    }

    char time_str[32];
    size_t time_len = gt - lt - 1;
    if (time_len == 0 || time_len >= sizeof(time_str)) return;
    snprintf(time_str, sizeof(time_str), "%.*s", (int)time_len, lt + 1);
    char *endptr;
    double time = strtod(time_str, &endptr);
    if (endptr != time_str + time_len) return;

    const char *paren = strchr(line, '(');
    if (!paren) return;
    size_t name_len = paren - line;
    if (name_len == 0 || name_len >= sizeof(syscalls[0].name)) return;

    char name[64];
    strncpy(name, line, name_len);
    name[name_len] = '\0';
    update_stat(name, time);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s COMMAND [ARG]...\n", argv[0]);
        return EXIT_FAILURE;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return EXIT_FAILURE;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (pid == 0) { // Child
        close(pipefd[0]);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        char *strace_argv[argc + 1];
        strace_argv[0] = "strace";
        strace_argv[1] = "-T";
        for (int i = 1; i < argc; i++) {
            strace_argv[i + 1] = argv[i];
        }
        strace_argv[argc + 1] = NULL;

        char *paths[] = {"/usr/bin/strace", "/bin/strace"};
        extern char **environ;
        for (int i = 0; i < 2; i++) {
            if (access(paths[i], X_OK) == 0) {
                execve(paths[i], strace_argv, environ);
                perror("execve");
                exit(EXIT_FAILURE);
            }
        }
        fprintf(stderr, "sperf: strace not found\n");
        exit(EXIT_FAILURE);
    } else { // Parent
        close(pipefd[1]);
        struct timeval last_output;
        gettimeofday(&last_output, NULL);

        char buffer[BUFFER_SIZE];
        size_t buffer_pos = 0;

        while (1) {
            struct timeval now;
            gettimeofday(&now, NULL);
            double elapsed = (now.tv_sec - last_output.tv_sec) +
                             (now.tv_usec - last_output.tv_usec) / 1000000.0;

            if (elapsed >= 0.1) {
                print_top5();
                last_output = now;
            }

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(pipefd[0], &read_fds);

            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = (0.1 - elapsed) * 1000000;
            if (timeout.tv_usec < 0) timeout.tv_usec = 0;

            int ret = select(pipefd[0] + 1, &read_fds, NULL, NULL, &timeout);
            if (ret == -1) {
                if (errno == EINTR) continue;
                perror("select");
                break;
            } else if (ret == 0) {
                print_top5();
                gettimeofday(&last_output, NULL);
            } else {
                ssize_t nread = read(pipefd[0], buffer + buffer_pos, sizeof(buffer) - buffer_pos - 1);
                if (nread < 0) {
                    if (errno == EINTR) continue;
                    perror("read");
                    break;
                } else if (nread == 0) {
                    print_top5();
                    break;
                } else {
                    buffer_pos += nread;
                    buffer[buffer_pos] = '\0';

                    char *line_start = buffer;
                    char *line_end;
                    while ((line_end = strchr(line_start, '\n')) != NULL) {
                        *line_end = '\0';
                        process_line(line_start);
                        line_start = line_end + 1;
                    }

                    size_t remaining = buffer + buffer_pos - line_start;
                    memmove(buffer, line_start, remaining);
                    buffer_pos = remaining;
                }
            }
        }

        close(pipefd[0]);
        waitpid(pid, NULL, 0);
    }

    return EXIT_SUCCESS;
}