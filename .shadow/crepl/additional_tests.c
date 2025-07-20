// Additional test cases for CREPL
#include <testkit.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// Function declarations
bool compile_and_load_function(const char* function_def);
bool evaluate_expression(const char* expression, int* result);
bool is_function_definition(const char* line);

// Test function recognition
UnitTest(test_recognize_int_function) {
    bool result = is_function_definition("int test() { return 1; }");
    tk_assert(result == true, "Should recognize int function definition");
}

UnitTest(test_recognize_void_function) {
    bool result = is_function_definition("void test() { printf(\"test\"); }");
    tk_assert(result == true, "Should recognize void function definition");
}

UnitTest(test_recognize_with_whitespace) {
    bool result = is_function_definition("  int test() { return 1; }");
    tk_assert(result == true, "Should recognize function with leading whitespace");
}

UnitTest(test_not_recognize_declaration) {
    bool result = is_function_definition("int test();");
    tk_assert(result == false, "Should not recognize function declaration");
}

UnitTest(test_not_recognize_expression) {
    bool result = is_function_definition("test() + 5");
    tk_assert(result == false, "Should not recognize expression as function");
}

// Test complex expressions
UnitTest(test_evaluate_parentheses) {
    int result_value;
    bool result = evaluate_expression("(5 + 3) * 2", &result_value);
    tk_assert(result == true, "Should evaluate expression with parentheses");
    tk_assert(result_value == 16, "Result should be 16");
}

UnitTest(test_evaluate_negative_numbers) {
    int result_value;
    bool result = evaluate_expression("-10 + 15", &result_value);
    tk_assert(result == true, "Should evaluate expression with negative numbers");
    tk_assert(result_value == 5, "Result should be 5");
}

// Test function with parameters
UnitTest(test_function_with_parameters) {
    bool result = compile_and_load_function("int add_numbers(int a, int b) { return a + b; }");
    tk_assert(result == true, "Should compile function with parameters");
    
    int result_value;
    bool eval_result = evaluate_expression("add_numbers(10, 20)", &result_value);
    tk_assert(eval_result == true, "Should evaluate function call with parameters");
    tk_assert(result_value == 30, "Result should be 30");
}

// Test recursive function
UnitTest(test_recursive_function) {
    bool result = compile_and_load_function("int factorial(int n) { if (n <= 1) return 1; return n * factorial(n-1); }");
    tk_assert(result == true, "Should compile recursive function");
    
    int result_value;
    bool eval_result = evaluate_expression("factorial(4)", &result_value);
    tk_assert(eval_result == true, "Should evaluate recursive function call");
    tk_assert(result_value == 24, "factorial(4) should be 24");
}

// Test function calling math library
UnitTest(test_math_library_function) {
    bool result = compile_and_load_function("int abs_value(int x) { return abs(x); }");
    tk_assert(result == true, "Should compile function using math library");
    
    int result_value;
    bool eval_result = evaluate_expression("abs_value(-42)", &result_value);
    tk_assert(eval_result == true, "Should evaluate function using abs()");
    tk_assert(result_value == 42, "abs(-42) should be 42");
}

// Test multiple function dependencies
UnitTest(test_multiple_function_dependencies) {
    // Define first function
    bool result1 = compile_and_load_function("int get_base() { return 10; }");
    tk_assert(result1 == true, "Should compile first function");
    
    // Define second function that uses first
    bool result2 = compile_and_load_function("int get_double() { return get_base() * 2; }");
    tk_assert(result2 == true, "Should compile second function");
    
    // Define third function that uses both
    bool result3 = compile_and_load_function("int get_sum() { return get_base() + get_double(); }");
    tk_assert(result3 == true, "Should compile third function");
    
    // Test evaluation
    int result_value;
    bool eval_result = evaluate_expression("get_sum()", &result_value);
    tk_assert(eval_result == true, "Should evaluate complex function call");
    tk_assert(result_value == 30, "get_sum() should be 30 (10 + 20)");
}

// Test error cases
UnitTest(test_null_function_definition) {
    bool result = compile_and_load_function(NULL);
    tk_assert(result == false, "Should handle NULL function definition");
}

UnitTest(test_empty_function_definition) {
    bool result = compile_and_load_function("");
    tk_assert(result == false, "Should handle empty function definition");
}

UnitTest(test_null_expression) {
    int result_value;
    bool result = evaluate_expression(NULL, &result_value);
    tk_assert(result == false, "Should handle NULL expression");
}

UnitTest(test_empty_expression) {
    int result_value;
    bool result = evaluate_expression("", &result_value);
    tk_assert(result == false, "Should handle empty expression");
}

// Test with different return types
UnitTest(test_char_function) {
    bool result = compile_and_load_function("char get_char() { return 'A'; }");
    tk_assert(result == true, "Should compile char function");
    
    int result_value;
    bool eval_result = evaluate_expression("get_char()", &result_value);
    tk_assert(eval_result == true, "Should evaluate char function");
    tk_assert(result_value == 65, "Result should be ASCII value of 'A'");
}

UnitTest(test_float_function) {
    bool result = compile_and_load_function("float get_pi() { return 3.14; }");
    tk_assert(result == true, "Should compile float function");
    
    // Note: This will truncate to int in current implementation
    int result_value;
    bool eval_result = evaluate_expression("(int)get_pi()", &result_value);
    tk_assert(eval_result == true, "Should evaluate cast float function");
    tk_assert(result_value == 3, "Result should be 3 (truncated)");
}
