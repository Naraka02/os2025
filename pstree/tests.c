#include <testkit.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// ======================== System Tests ========================

// Test the basic functionality without any arguments
SystemTest(basic_no_args, 
           ((const char *[]){})) {
    tk_assert(result->exit_status == 0, 
              "Basic pstree command should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Output should not be empty");
}

// Test the -p (--show-pids) option
SystemTest(show_pids_short, 
           ((const char *[]){"-p"})) {
    tk_assert(result->exit_status == 0, 
              "pstree -p should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Output should not be empty");
    // Check for presence of PIDs in output (numbers in parentheses)
    tk_assert(strstr(result->output, "(") != NULL, 
              "Output should contain PIDs in parentheses");
}

SystemTest(show_pids_long, 
           ((const char *[]){"--show-pids"})) {
    tk_assert(result->exit_status == 0, 
              "pstree --show-pids should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Output should not be empty");
    // Check for presence of PIDs in output (numbers in parentheses)
    tk_assert(strstr(result->output, "(") != NULL, 
              "Output should contain PIDs in parentheses");
}

// Test the -n (--numeric-sort) option
SystemTest(numeric_sort_short, 
           ((const char *[]){"-n"})) {
    tk_assert(result->exit_status == 0, 
              "pstree -n should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Output should not be empty");
    // Note: Testing the actual sorting would require parsing the output
}

SystemTest(numeric_sort_long, 
           ((const char *[]){"--numeric-sort"})) {
    tk_assert(result->exit_status == 0, 
              "pstree --numeric-sort should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Output should not be empty");
}

// Test the -V (--version) option
SystemTest(version_short, 
           ((const char *[]){"-V"})) {
    tk_assert(result->exit_status == 0, 
              "pstree -V should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Version information should not be empty");
    // Check for version-like information
    tk_assert(strstr(result->output, "pstree") != NULL,
              "Output should contain version information");
}

SystemTest(version_long, 
           ((const char *[]){"--version"})) {
    tk_assert(result->exit_status == 0, 
              "pstree --version should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Version information should not be empty");
    // Check for version-like information
    tk_assert(strstr(result->output, "pstree") != NULL,
              "Output should contain version information");
}

// Test combinations of options
SystemTest(show_pids_and_numeric_sort, 
           ((const char *[]){"-p", "-n"})) {
    tk_assert(result->exit_status == 0, 
              "pstree -p -n should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Output should not be empty");
    // Check for presence of PIDs in output
    tk_assert(strstr(result->output, "(") != NULL, 
              "Output should contain PIDs in parentheses");
}

SystemTest(all_options_long, 
           ((const char *[]){"--show-pids", "--numeric-sort"})) {
    tk_assert(result->exit_status == 0, 
              "pstree --show-pids --numeric-sort should exit with status 0, got %d", 
              result->exit_status);
    tk_assert(strlen(result->output) > 0, 
              "Output should not be empty");
    // Check for presence of PIDs in output
    tk_assert(strstr(result->output, "(") != NULL, 
              "Output should contain PIDs in parentheses");
}

SystemTest(invalid_option, 
           ((const char *[]){"--invalid-option"})) {
    // Program should exit with non-zero status for invalid options
    tk_assert(result->exit_status != 0, 
              "pstree with invalid option should exit with non-zero status");
    // Should print usage information
    tk_assert(strstr(result->output, "usage") != NULL || 
              strstr(result->output, "Usage") != NULL || 
              strstr(result->output, "invalid") != NULL || 
              strstr(result->output, "Invalid") != NULL,
              "Output should mention invalid option or show usage");
}
