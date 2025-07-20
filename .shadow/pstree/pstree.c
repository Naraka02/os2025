#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/types.h>
#include <getopt.h>

#define MAX_PROCESSES 32768
#define MAX_NAME_LEN 256
#define VERSION "1.0.0"

typedef struct process {
    pid_t pid;
    pid_t ppid;
    char name[MAX_NAME_LEN];
    struct process **children;
    int child_count;
    int child_capacity;
} Process;

static Process processes[MAX_PROCESSES];
static int process_count = 0;
static bool show_pids = false;
static bool numeric_sort = false;

// Function prototypes
void print_usage(void);
void print_version(void);
int read_processes(void);
int parse_proc_stat(const char *path, Process *proc);
void build_tree(void);
void print_tree(Process *proc, const char *prefix, bool is_last);
Process *find_process(pid_t pid);
int compare_by_pid(const void *a, const void *b);
int compare_by_name(const void *a, const void *b);
void add_child(Process *parent, Process *child);

int main(int argc, char *argv[]) {
    int opt;
    struct option long_options[] = {
        {"show-pids", no_argument, 0, 'p'},
        {"numeric-sort", no_argument, 0, 'n'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "pnVh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                show_pids = true;
                break;
            case 'n':
                numeric_sort = true;
                break;
            case 'V':
                print_version();
                return 0;
            case 'h':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }

    if (read_processes() < 0) {
        fprintf(stderr, "Error reading processes\n");
        return 1;
    }

    build_tree();

    // Find init process (pid 1) or systemd to start the tree
    Process *root = find_process(1);
    if (!root) {
        // If no init process, find the process with lowest pid that has no parent in our list
        for (int i = 0; i < process_count; i++) {
            if (find_process(processes[i].ppid) == NULL) {
                root = &processes[i];
                break;
            }
        }
    }

    if (root) {
        print_tree(root, "", true);
    }

    // Clean up allocated memory
    for (int i = 0; i < process_count; i++) {
        if (processes[i].children) {
            free(processes[i].children);
        }
    }

    return 0;
}

void print_usage(void) {
    printf("Usage: pstree [OPTION]...\n");
    printf("Display running processes as a tree.\n\n");
    printf("Options:\n");
    printf("  -p, --show-pids     show PIDs\n");
    printf("  -n, --numeric-sort  sort children by PID numerically\n");
    printf("  -V, --version       display version information\n");
    printf("  -h, --help          display this help and exit\n");
}

void print_version(void) {
    printf("pstree %s\n", VERSION);
}

int read_processes(void) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc");
        return -1;
    }

    struct dirent *entry;
    process_count = 0;

    while ((entry = readdir(proc_dir)) != NULL && process_count < MAX_PROCESSES) {
        // Check if directory name is a number (PID)
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) {
            continue;
        }

        char stat_path[256];
        snprintf(stat_path, sizeof(stat_path), "/proc/%s/stat", entry->d_name);

        if (parse_proc_stat(stat_path, &processes[process_count]) == 0) {
            process_count++;
        }
    }

    closedir(proc_dir);
    return process_count;
}

int parse_proc_stat(const char *path, Process *proc) {
    FILE *file = fopen(path, "r");
    if (!file) {
        return -1;
    }

    char comm[MAX_NAME_LEN];
    char state;
    
    // Parse /proc/[pid]/stat format
    int parsed = fscanf(file, "%d %s %c %d", 
                       &proc->pid, comm, &state, &proc->ppid);
    
    fclose(file);
    
    if (parsed != 4) {
        return -1;
    }

    // Remove parentheses from command name
    if (strlen(comm) >= 2 && comm[0] == '(' && comm[strlen(comm)-1] == ')') {
        comm[strlen(comm)-1] = '\0';
        strcpy(proc->name, comm + 1);
    } else {
        strcpy(proc->name, comm);
    }

    proc->children = NULL;
    proc->child_count = 0;
    proc->child_capacity = 0;

    return 0;
}

Process *find_process(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (processes[i].pid == pid) {
            return &processes[i];
        }
    }
    return NULL;
}

void add_child(Process *parent, Process *child) {
    if (parent->child_count >= parent->child_capacity) {
        parent->child_capacity = parent->child_capacity == 0 ? 4 : parent->child_capacity * 2;
        parent->children = realloc(parent->children, 
                                 parent->child_capacity * sizeof(Process*));
    }
    parent->children[parent->child_count++] = child;
}

void build_tree(void) {
    // Build parent-child relationships
    for (int i = 0; i < process_count; i++) {
        Process *parent = find_process(processes[i].ppid);
        if (parent && parent != &processes[i]) {
            add_child(parent, &processes[i]);
        }
    }

    // Sort children for each process
    for (int i = 0; i < process_count; i++) {
        if (processes[i].child_count > 0) {
            if (numeric_sort) {
                qsort(processes[i].children, processes[i].child_count, 
                      sizeof(Process*), compare_by_pid);
            } else {
                qsort(processes[i].children, processes[i].child_count, 
                      sizeof(Process*), compare_by_name);
            }
        }
    }
}

int compare_by_pid(const void *a, const void *b) {
    Process *proc_a = *(Process**)a;
    Process *proc_b = *(Process**)b;
    return proc_a->pid - proc_b->pid;
}

int compare_by_name(const void *a, const void *b) {
    Process *proc_a = *(Process**)a;
    Process *proc_b = *(Process**)b;
    return strcmp(proc_a->name, proc_b->name);
}

void print_tree(Process *proc, const char *prefix, bool is_last) {
    if (!proc) return;

    // Print current process
    printf("%s", prefix);
    printf("%s", is_last ? "└─" : "├─");
    
    if (show_pids) {
        printf("%s(%d)\n", proc->name, proc->pid);
    } else {
        printf("%s\n", proc->name);
    }

    // Print children
    for (int i = 0; i < proc->child_count; i++) {
        char new_prefix[1024];
        snprintf(new_prefix, sizeof(new_prefix), "%s%s", prefix, 
                is_last ? "  " : "│ ");
        
        bool child_is_last = (i == proc->child_count - 1);
        print_tree(proc->children[i], new_prefix, child_is_last);
    }
}
