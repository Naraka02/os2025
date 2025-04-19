#include <testkit.h>
#include <string.h>

// You may need to change time limit in testkit.h

SystemTest(test_inference, ((const char *[]){ "31373", "612", "338", "635", "281", "4998", "3715", "351", "2506" })) {
    tk_assert(result->exit_status == 0, "Must exit 0");
    tk_assert(
        strstr(result->output, "852") != NULL,
        "Must print correct token"
    );
}
