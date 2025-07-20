#include "testkit.h"
#include <string.h>

// TestKit lacks support of fork().
// Write unit tests here.

int parse_strace_line(char *line, char *syscall_name, double *time);

UnitTest(test_parse_strace_line) {
    char line[] = "openat(AT_FDCWD, \"/etc/ld.so.cache\", O_RDONLY|O_CLOEXEC) = 3 <0.000123>";
    char syscall_name[64];
    double time;
    
    int result = parse_strace_line(line, syscall_name, &time);
    
    tk_assert(result == 1, "Should successfully parse strace line");
    tk_assert(strcmp(syscall_name, "openat") == 0, "Should extract correct syscall name");
    tk_assert(time == 0.000123, "Should extract correct time");
}

UnitTest(test_parse_strace_line_no_time) {
    char line[] = "write(1, \"hello\\n\", 6) = 6";
    char syscall_name[64];
    double time;
    
    int result = parse_strace_line(line, syscall_name, &time);
    
    tk_assert(result == 0, "Should fail to parse line without timing information");
}
