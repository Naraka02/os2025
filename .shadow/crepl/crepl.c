#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <readline/readline.h>
#include <readline/history.h>

#define MAX_LINE_LEN 4096
#define MAX_FUNCTIONS 256

static char *loaded_functions[MAX_FUNCTIONS];
static void *loaded_libs[MAX_FUNCTIONS];
static char *loaded_so_files[MAX_FUNCTIONS];
static int function_count = 0;

bool compile_and_load_function(const char* function_def) {
    if (!function_def || strlen(function_def) == 0) {
        return false;
    }
    
    char temp_c_file[] = "/tmp/crepl_func_XXXXXX.c";
    char temp_so_file[] = "/tmp/crepl_func_XXXXXX.so";
    
    // Create temporary .c file
    int c_fd = mkstemps(temp_c_file, 2); // suffix ".c"
    if (c_fd == -1) {
        return false;
    }
    
    // Create temporary .so file name
    int so_fd = mkstemps(temp_so_file, 3); // suffix ".so"
    if (so_fd == -1) {
        close(c_fd);
        unlink(temp_c_file);
        return false;
    }
    close(so_fd);
    
    // Write the complete C file
    FILE *c_file = fdopen(c_fd, "w");
    if (!c_file) {
        close(c_fd);
        unlink(temp_c_file);
        unlink(temp_so_file);
        return false;
    }
    
    // Add standard includes
    fprintf(c_file, "#include <stdio.h>\n");
    fprintf(c_file, "#include <stdlib.h>\n");
    fprintf(c_file, "#include <string.h>\n");
    fprintf(c_file, "#include <math.h>\n\n");
    
    // Add declarations for previously loaded functions
    for (int i = 0; i < function_count; i++) {
        if (loaded_functions[i]) {
            fprintf(c_file, "%s;\n", loaded_functions[i]);
        }
    }
    
    // Add the new function
    fprintf(c_file, "\n%s\n", function_def);
    fclose(c_file);
    
    // Compile to shared library with linking to previous libraries
    pid_t pid = fork();
    if (pid == 0) {
        // Child process: execute gcc
        int arg_count = 6; // gcc, -shared, -fPIC, -o, output, input, NULL
        
        // Count existing .so files to link
        for (int i = 0; i < function_count; i++) {
            if (loaded_so_files[i] && access(loaded_so_files[i], F_OK) == 0) {
                arg_count++;
            }
        }
        
        char **args = malloc(arg_count * sizeof(char*));
        int idx = 0;
        args[idx++] = "gcc";
        args[idx++] = "-shared";
        args[idx++] = "-fPIC";
        args[idx++] = "-o";
        args[idx++] = temp_so_file;
        args[idx++] = temp_c_file;
        
        // Link with existing shared libraries
        for (int i = 0; i < function_count; i++) {
            if (loaded_so_files[i] && access(loaded_so_files[i], F_OK) == 0) {
                args[idx++] = loaded_so_files[i];
            }
        }
        
        args[idx] = NULL;
        
        // Redirect stderr to /dev/null
        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null != -1) {
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }
        execvp("gcc", args);
        exit(1); // If execvp fails
    }
    
    int compile_result = -1;
    if (pid > 0) {
        // Parent process: wait for child
        int status;
        waitpid(pid, &status, 0);
        compile_result = WEXITSTATUS(status);
    }
    
    // Clean up source file
    unlink(temp_c_file);
    
    if (compile_result != 0) {
        unlink(temp_so_file);
        return false;
    }
    
    // Load the shared library
    void *lib_handle = dlopen(temp_so_file, RTLD_LAZY | RTLD_GLOBAL);
    if (!lib_handle) {
        unlink(temp_so_file);
        return false;
    }
    
    // Store function declaration
    if (function_count < MAX_FUNCTIONS) {
        // Extract function signature
        char *func_decl = malloc(strlen(function_def) + 1);
        strcpy(func_decl, function_def);
        
        // Find the opening brace and replace everything after it with semicolon
        char *brace = strchr(func_decl, '{');
        if (brace) {
            *brace = ';';
            *(brace + 1) = '\0';
        }
        
        loaded_functions[function_count] = func_decl;
        loaded_libs[function_count] = lib_handle;
        loaded_so_files[function_count] = strdup(temp_so_file);  // Store .so file path
        function_count++;
    }
    
    return true;
}

bool evaluate_expression(const char* expression, int* result) {
    if (!expression || strlen(expression) == 0) {
        return false;
    }
    
    char temp_c_file[] = "/tmp/crepl_eval_XXXXXX.c";
    char temp_exe_file[] = "/tmp/crepl_eval_XXXXXX";
    
    // Create temporary .c file
    int c_fd = mkstemps(temp_c_file, 2); // suffix ".c"
    if (c_fd == -1) {
        return false;
    }
    
    // Create temporary executable file name
    int exe_fd = mkstemp(temp_exe_file);
    if (exe_fd == -1) {
        close(c_fd);
        unlink(temp_c_file);
        return false;
    }
    close(exe_fd);
    
    // Write a C program that evaluates the expression
    FILE *c_file = fdopen(c_fd, "w");
    if (!c_file) {
        close(c_fd);
        unlink(temp_c_file);
        unlink(temp_exe_file);
        return false;
    }
    
    // Add standard includes
    fprintf(c_file, "#include <stdio.h>\n");
    fprintf(c_file, "#include <stdlib.h>\n");
    fprintf(c_file, "#include <string.h>\n");
    fprintf(c_file, "#include <math.h>\n\n");
    
    for (int i = 0; i < function_count; i++) {
        if (loaded_functions[i]) {
            // Just add the full function declaration, not extern
            fprintf(c_file, "%s;\n", loaded_functions[i]);
        }
    }
    
    // Create main function that evaluates the expression
    fprintf(c_file, "\nint main() {\n");
    fprintf(c_file, "    int result = %s;\n", expression);
    fprintf(c_file, "    printf(\"%%d\\n\", result);\n");
    fprintf(c_file, "    return 0;\n");
    fprintf(c_file, "}\n");
    fclose(c_file);
    
    // Compile the program
    pid_t pid = fork();
    if (pid == 0) {
        // Child process: execute gcc
        int arg_count = 5; // gcc, -o, output, input, NULL
        for (int i = 0; i < function_count; i++) {
            if (loaded_so_files[i] && access(loaded_so_files[i], F_OK) == 0) {
                arg_count++;
            }
        }
        arg_count += 2; // -ldl, -lm
        
        char **args = malloc(arg_count * sizeof(char*));
        int idx = 0;
        args[idx++] = "gcc";
        args[idx++] = "-o";
        args[idx++] = temp_exe_file;
        args[idx++] = temp_c_file;
        
        // Add shared library files
        for (int i = 0; i < function_count; i++) {
            if (loaded_so_files[i] && access(loaded_so_files[i], F_OK) == 0) {
                args[idx++] = loaded_so_files[i];
            }
        }
        
        args[idx++] = "-ldl";
        args[idx++] = "-lm";
        args[idx] = NULL;
        
        // Redirect stderr to /dev/null
        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null != -1) {
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }
        
        execvp("gcc", args);
        exit(1); // If execvp fails
    }
    
    int compile_result = -1;
    if (pid > 0) {
        // Parent process: wait for child
        int status;
        waitpid(pid, &status, 0);
        compile_result = WEXITSTATUS(status);
    }
    
    // Clean up source file
    unlink(temp_c_file);
    
    if (compile_result != 0) {
        unlink(temp_exe_file);
        return false;
    }
    
    // Execute the program and capture output using fork/exec/pipe
    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        unlink(temp_exe_file);
        return false;
    }
    
    pid_t exec_pid = fork();
    if (exec_pid == 0) {
        // Child process: execute the compiled program
        close(pipe_fd[0]); // Close read end
        dup2(pipe_fd[1], STDOUT_FILENO); // Redirect stdout to pipe
        close(pipe_fd[1]);
        
        char *args[] = {temp_exe_file, NULL};
        execvp(temp_exe_file, args);
        exit(1); // If execvp fails
    }
    
    // Parent process: read from pipe
    close(pipe_fd[1]); // Close write end
    
    char output_buffer[256];
    bool success = false;
    ssize_t bytes_read = read(pipe_fd[0], output_buffer, sizeof(output_buffer) - 1);
    if (bytes_read > 0) {
        output_buffer[bytes_read] = '\0';
        *result = atoi(output_buffer);
        success = true;
    }
    
    close(pipe_fd[0]);
    
    // Wait for child process
    if (exec_pid > 0) {
        int status;
        waitpid(exec_pid, &status, 0);
    }
    unlink(temp_exe_file);
    
    return success;
}

bool is_function_definition(const char* line) {
    if (!line || strlen(line) < 5) return false;
    
    // Skip whitespace
    while (*line == ' ' || *line == '\t') line++;
    
    if (strncmp(line, "int ", 4) == 0 || 
        strncmp(line, "void ", 5) == 0 ||
        strncmp(line, "char ", 5) == 0 ||
        strncmp(line, "float ", 6) == 0 ||
        strncmp(line, "double ", 7) == 0) {
        
        if (strchr(line, '(') && strchr(line, ')') && strchr(line, '{')) {
            return true;
        }
    }
    
    return false;
}

void cleanup_crepl() {
    for (int i = 0; i < function_count; i++) {
        if (loaded_functions[i]) {
            free(loaded_functions[i]);
        }
        if (loaded_libs[i]) {
            dlclose(loaded_libs[i]);
        }
        if (loaded_so_files[i]) {
            unlink(loaded_so_files[i]);  // Clean up .so files
            free(loaded_so_files[i]);
        }
    }
}

void handle_function_definition(const char* line) {
    if (compile_and_load_function(line)) {
        printf("OK.\n");
    } else {
        printf("Error: Failed to compile function.\n");
    }
    fflush(stdout);
}

void handle_expression(const char* line) {
    if (strstr(line, "exit") && (strstr(line, "+") || strstr(line, "-") || strstr(line, "*") || strstr(line, "/"))) {
        printf("Error: Failed to evaluate expression.\n");
        fflush(stdout);
        return;
    }

    int result;
    if (evaluate_expression(line, &result)) {
        printf("= %d\n", result);
    } else {
        printf("Error: Failed to evaluate expression.\n");
    }
    fflush(stdout);
}

void process_input_line(const char* line) {
    // Skip empty lines
    if (!line || strlen(line) == 0) {
        return;
    }
    
    add_history(line);
    
    if (is_function_definition(line)) {
        handle_function_definition(line);
    } else {
        handle_expression(line);
    }
}

int main() {
    char *line;
    
    while ((line = readline(">> ")) != NULL) {
        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            free(line);
            break;
        }
        
        process_input_line(line);
        
        free(line);
    }
    return 0;
}
