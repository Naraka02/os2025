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
#include <ctype.h>

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
    int status_code = 200; // Default status code

    // Read request
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        return;
    }
    buffer[bytes_received] = '\0';

    printf("Got a new request:\n%s\n", buffer);

    // Parse the request line
    char method[16], path[MAX_PATH_LENGTH], version[16];
    if (sscanf(buffer, "%15s %1023s %15s", method, path, version) != 3) {
        // Invalid request format
        const char *response = "HTTP/1.1 404 Not Found\r\n\r\nInvalid request";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    }

    // Check if this is a CGI request
    if (strncmp(path, "/cgi-bin/", 9) != 0) {
        // Not a CGI request, return 404
        const char *response = "HTTP/1.1 404 Not Found\r\n\r\nNot a CGI request";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    }

    // Extract the CGI script name
    char script_name[MAX_PATH_LENGTH];
    snprintf(script_name, sizeof(script_name), "%s", path + 9); // Skip "/cgi-bin/"

    // Check for query string
    char *query_string = strchr(script_name, '?');
    if (query_string) {
        *query_string = '\0'; // Terminate script name at '?'
        query_string++; // Move past the '?'
    } else {
        query_string = "";
    }

    char full_path[MAX_PATH_LENGTH];
    snprintf(full_path, sizeof(full_path), "./cgi-bin/%1023s", script_name);

    // Set environment variables for CGI
    setenv("REQUEST_METHOD", method, 1);
    setenv("QUERY_STRING", query_string, 1);

    // Create a pipe to capture CGI output
    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        perror("Pipe creation failed");
        status_code = 500; // Internal Server Error
        close(client_socket);
        goto send_error;
    }

    // Fork a child process to execute the CGI script
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        status_code = 500; // Internal Server Error
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        close(client_socket);
        goto send_error;
    }

    if (pid == 0) {
        // Child process: close the read end of the pipe
        close(pipe_fd[0]);

        // Redirect stdout to the write end of the pipe
        dup2(pipe_fd[1], STDOUT_FILENO);
        close(pipe_fd[1]);

        // Execute the CGI script
        execl(full_path, full_path, (char *)NULL);

        // If execl fails, send an error message to the pipe
        perror("Exec failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process: close the write end of the pipe
        close(pipe_fd[1]);

        // Read output from the CGI script
        char cgi_output[BUFFER_SIZE];
        int output_length = 0;
        int bytes_read;

        while ((bytes_read = read(pipe_fd[0], cgi_output + output_length, BUFFER_SIZE - output_length - 1)) > 0) {
            output_length += bytes_read;
        }

        close(pipe_fd[0]);
        cgi_output[output_length] = '\0';

        // Wait for the child process to finish
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) != 0) {
            status_code = 501;
            goto send_error;
        }

        if (WEXITSTATUS(status) != 0) {
            status_code = 500;
            goto send_error;
        }

        if (strncmp(cgi_output, "HTTP/", 5) == 0) {
            char *status_start = cgi_output;
            // Skip past "HTTP/1.x "
            while (*status_start && *status_start != ' ') status_start++;
            if (*status_start) status_start++;
            
            // Extract the status code
            if (isdigit(*status_start)) {
                status_code = atoi(status_start);
            }
        }

        // Send response
        send(client_socket, cgi_output, output_length, 0);
            
        // Log the request
        log_request(method, path, status_code);

        close(client_socket);
        return;

send_error:
        // Send error response if CGI execution failed
        char error_response[256];
        sprintf(error_response, "HTTP/1.1 %d %s\r\n\r\nError executing CGI script", 
               status_code, status_code == 500 ? "Internal Server Error" : "Bad Request");
        send(client_socket, error_response, strlen(error_response), 0);
        log_request(method, path, status_code);
        close(client_socket);
        return;
    }
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
