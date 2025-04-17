#ifdef FREESTANDING

// This checks whether your code works for
// freestanding environments.

void _start() {
}

int main() {
    return 0;
}

#else

// main() is defined in tests/main.c

#endif
