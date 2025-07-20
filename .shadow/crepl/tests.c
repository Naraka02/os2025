#include <testkit.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// Feel free to rename them.
bool compile_and_load_function(const char* function_def);
bool evaluate_expression(const char* expression, int* result);

UnitTest(test_compile_valid_function) {
    bool result = compile_and_load_function("int test_func() { return 42; }");
    tk_assert(result == true, "Should successfully compile valid function");
}

UnitTest(test_compile_function_using_previous) {
    compile_and_load_function("int test_func() { return 42; }");

    bool result = compile_and_load_function("int test_func2() { return test_func(); }");
    tk_assert(result == true, "Should successfully compile function using previous function");
}

UnitTest(test_compile_invalid_syntax) {
    bool result = compile_and_load_function("int invalid_func() { return 42");
    tk_assert(result == false, "Should fail on syntax error");
}

UnitTest(test_evaluate_simple_constant) {
    int result_value;
    bool result = evaluate_expression("42", &result_value);
    tk_assert(result == true, "Should evaluate simple constant");
    tk_assert(result_value == 42, "Result should be 42");
}

UnitTest(test_evaluate_arithmetic) {
    int result_value;
    bool result = evaluate_expression("21 + 21", &result_value);
    tk_assert(result == true, "Should evaluate arithmetic expression");
    tk_assert(result_value == 42, "Result should be 42");
}

UnitTest(test_evaluate_function_call) {
    compile_and_load_function("int test_eval() { return 100; }");

    int result_value;
    bool result = evaluate_expression("test_eval()", &result_value);
    tk_assert(result == true, "Should evaluate function call");
    tk_assert(result_value == 100, "Result should be 100");
}

UnitTest(test_evaluate_complex_expression) {
    compile_and_load_function("int test_eval() { return 100; }");

    int result_value;
    bool result = evaluate_expression("test_eval() / 2", &result_value);
    tk_assert(result == true, "Should evaluate complex expression");
    tk_assert(result_value == 50, "Result should be 50");
}

UnitTest(test_evaluate_undefined_function) {
    int result_value;
    bool result = evaluate_expression("undefined_function()", &result_value);
    tk_assert(result == false, "Should fail on undefined function");
}

UnitTest(test_evaluate_syntax_error) {
    int result_value;
    bool result = evaluate_expression("21 +", &result_value);
    tk_assert(result == false, "Should fail on syntax error");
}
