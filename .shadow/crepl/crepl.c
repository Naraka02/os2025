#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <readline/readline.h>
#include <readline/history.h>

#define MAX_LINE_LEN 4096
#define MAX_FUNCTIONS 256

// Track loaded functions and shared libraries
static char *loaded_functions[MAX_FUNCTIONS];
static void *loaded_libs[MAX_FUNCTIONS];
static char *loaded_so_files[MAX_FUNCTIONS];  // Store .so file paths
static int function_count = 0;

// Compile a function definition and load it
bool compile_and_load_function(const char* function_def) {
    if (!function_def || strlen(function_def) == 0) {
        return false;
    }
    
    // Create unique temporary files
    char temp_c_file[256];
    char temp_so_file[256];
    static int file_counter = 0;
    
    snprintf(temp_c_file, sizeof(temp_c_file), "/tmp/crepl_func_%d_%d.c", getpid(), file_counter);
    snprintf(temp_so_file, sizeof(temp_so_file), "/tmp/crepl_func_%d_%d.so", getpid(), file_counter);
    file_counter++;
    
    // Write the complete C file with includes and previous function declarations
    FILE *c_file = fopen(temp_c_file, "w");
    if (!c_file) {
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
    
    // Compile to shared library
    char compile_cmd[1024];
    snprintf(compile_cmd, sizeof(compile_cmd), 
             "gcc -shared -fPIC -o %s %s 2>/dev/null", 
             temp_so_file, temp_c_file);
    
    int compile_result = system(compile_cmd);
    
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
    
    // Store function declaration for future use
    if (function_count < MAX_FUNCTIONS) {
        // Extract function signature for declaration
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

// Evaluate an expression
bool evaluate_expression(const char* expression, int* result) {
    if (!expression || strlen(expression) == 0) {
        return false;
    }
    
    // Create unique temporary files
    char temp_c_file[256];
    char temp_exe_file[256];
    static int eval_counter = 0;
    
    snprintf(temp_c_file, sizeof(temp_c_file), "/tmp/crepl_eval_%d_%d.c", getpid(), eval_counter);
    snprintf(temp_exe_file, sizeof(temp_exe_file), "/tmp/crepl_eval_%d_%d", getpid(), eval_counter);
    eval_counter++;
    
    // Write a C program that evaluates the expression
    FILE *c_file = fopen(temp_c_file, "w");
    if (!c_file) {
        return false;
    }
    
    // Add standard includes
    fprintf(c_file, "#include <stdio.h>\n");
    fprintf(c_file, "#include <stdlib.h>\n");
    fprintf(c_file, "#include <string.h>\n");
    fprintf(c_file, "#include <math.h>\n\n");
    
    // Add function definitions (not just declarations) for previously loaded functions
    for (int i = 0; i < function_count; i++) {
        if (loaded_functions[i]) {
            // Convert declaration back to a stub function
            char *func_decl = strdup(loaded_functions[i]);
            char *semicolon = strrchr(func_decl, ';');
            if (semicolon) {
                *semicolon = '\0';
                // Extract function name for a simple stub
                char *func_name = strrchr(func_decl, ' ');
                if (func_name) {
                    func_name++;
                    char *paren = strchr(func_name, '(');
                    if (paren) {
                        *paren = '\0';
                        fprintf(c_file, "extern int %s();\n", func_name);
                        *paren = '(';
                    }
                }
            }
            free(func_decl);
        }
    }
    
    // Create main function that evaluates the expression
    fprintf(c_file, "\nint main() {\n");
    fprintf(c_file, "    int result = %s;\n", expression);
    fprintf(c_file, "    printf(\"%%d\\n\", result);\n");
    fprintf(c_file, "    return 0;\n");
    fprintf(c_file, "}\n");
    fclose(c_file);
    
    // Build linking arguments for all loaded shared libraries
    char link_args[2048] = "";
    for (int i = 0; i < function_count; i++) {
        if (loaded_so_files[i] && access(loaded_so_files[i], F_OK) == 0) {
            strcat(link_args, " ");
            strcat(link_args, loaded_so_files[i]);
        }
    }
    
    // Compile the program
    char compile_cmd[2048];
    snprintf(compile_cmd, sizeof(compile_cmd), 
             "gcc -o %s %s %s -ldl -lm 2>/dev/null", 
             temp_exe_file, temp_c_file, link_args);
    
    int compile_result = system(compile_cmd);
    
    // Clean up source file
    unlink(temp_c_file);
    
    if (compile_result != 0) {
        unlink(temp_exe_file);
        return false;
    }
    
    // Execute the program and capture output
    char exec_cmd[512];
    snprintf(exec_cmd, sizeof(exec_cmd), "%s", temp_exe_file);
    
    FILE *output = popen(exec_cmd, "r");
    if (!output) {
        unlink(temp_exe_file);
        return false;
    }
    
    char output_buffer[256];
    bool success = false;
    if (fgets(output_buffer, sizeof(output_buffer), output)) {
        *result = atoi(output_buffer);
        success = true;
    }
    
    pclose(output);
    unlink(temp_exe_file);
    
    return success;
}

// Check if input looks like a function definition
bool is_function_definition(const char* line) {
    // Simple heuristic: contains both '(' and '{' and has a return type
    if (!line || strlen(line) < 5) return false;
    
    // Skip whitespace
    while (*line == ' ' || *line == '\t') line++;
    
    // Look for common return types
    if (strncmp(line, "int ", 4) == 0 || 
        strncmp(line, "void ", 5) == 0 ||
        strncmp(line, "char ", 5) == 0 ||
        strncmp(line, "float ", 6) == 0 ||
        strncmp(line, "double ", 7) == 0) {
        
        // Check for function signature pattern
        if (strchr(line, '(') && strchr(line, ')') && strchr(line, '{')) {
            return true;
        }
    }
    
    return false;
}

// Clean up function to free resources
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

// Wrapper function to handle function definition input
void handle_function_definition(const char* line) {
    if (compile_and_load_function(line)) {
        printf("Function compiled and loaded successfully.\n");
    } else {
        printf("Error: Failed to compile function.\n");
    }
    fflush(stdout);
}

// Wrapper function to handle expression evaluation
void handle_expression(const char* line) {
    int result;
    if (evaluate_expression(line, &result)) {
        printf("%d\n", result);
    } else {
        printf("Error: Failed to evaluate expression.\n");
    }
    fflush(stdout);
}

// Wrapper function to process a single line of input
void process_input_line(const char* line) {
    // Skip empty lines
    if (!line || strlen(line) == 0) {
        return;
    }
    
    // Add to history for readline
    add_history(line);
    
    // Check if it's a function definition or expression
    if (is_function_definition(line)) {
        handle_function_definition(line);
    } else {
        handle_expression(line);
    }
}

// Wrapper function for the main REPL loop
void run_repl() {
    char *line;
    
    printf("C REPL - Enter function definitions or expressions:\n");
    printf("Use Ctrl+D or 'exit' to quit.\n");
    
    while ((line = readline("> ")) != NULL) {
        // Check for exit command
        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            free(line);
            break;
        }
        
        // Process the input line
        process_input_line(line);
        
        // Free the readline allocated memory
        free(line);
    }
}

int main() {
    // Register cleanup function
    atexit(cleanup_crepl);
    
    // Run the REPL
    run_repl();
    
    printf("\nGoodbye!\n");
    return 0;
}
