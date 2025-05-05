#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

// Don't include these in another file.
#include "thread.h"
#include "thread-sync.h"

#define BUFFER_SIZE 4096
#define MAX_PATH_LENGTH 1024
#define DEFAULT_PORT 8080

// Revise this.
void handle_request(int client_socket);

// Call this.
void log_request(const char *method, const char *path, int status_code);

int main(int argc, char *argv[]) {
    // Socket variables
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Get port from command line or use default
    int port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;

    // Set up signal handler for SIGPIPE to prevent crashes
    // when client disconnects
    signal(SIGPIPE, SIG_IGN);

    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address
    // (prevents "Address already in use" errors)
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;         // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY; // Accept connections on any interface
    server_addr.sin_port = htons(port);       // Convert port to network byte order

    // Bind socket to address and port
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections with system-defined maximum backlog
    if (listen(server_socket, SOMAXCONN) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", port);

    // Main server loop - accept and process connections indefinitely
    while (1) {
        // Accept new client connection
        if ((client_socket = accept(server_socket,
                                    (struct sockaddr *)&client_addr,
                                    &client_len)) < 0) {
            perror("Accept failed");
            continue;  // Continue listening for other connections
        }

        // Set timeouts to prevent hanging on slow or dead connections
        struct timeval timeout;
        timeout.tv_sec = 30;  // 30 seconds timeout
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO,
                   (const char*)&timeout, sizeof(timeout));
        setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO,
                   (const char*)&timeout, sizeof(timeout));

        // Process the client request
        handle_request(client_socket);
    }

    // Clean up (note: this code is never reached in this example)
    close(server_socket);
    return 0;
}

void handle_request(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Read request
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        return;
    }
    buffer[bytes_received] = '\0';

    printf("Got a new request:\n%s\n", buffer);

    // Send "Under construction" response
    const char *response_body = "Under construction";
    int body_length = strlen(response_body);
    
    char content_length_header[64];
    sprintf(content_length_header, "Content-Length: %d\r\n", body_length);
    
    send(client_socket, "HTTP/1.1 200 OK\r\n", 17, 0);
    send(client_socket, "Content-Type: text/plain\r\n", 26, 0);
    send(client_socket, content_length_header, strlen(content_length_header), 0);
    send(client_socket, "Connection: close\r\n", 19, 0);
    send(client_socket, "\r\n", 2, 0);
    send(client_socket, response_body, body_length, 0);

    // Close the connection
    close(client_socket);
}

void log_request(const char *method, const char *path, int status_code) {
    time_t now;
    struct tm *tm_info;
    char timestamp[26];

    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    // In real systems, we write to a log file,
    // like /var/log/nginx/access.log
    printf("[%s] [%s] [%s] [%d]\n", timestamp, method, path, status_code);
    fflush(stdout);
}
