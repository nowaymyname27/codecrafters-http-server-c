#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>   // For threading

// Constants
#define BUFFER_SIZE 1024
#define METHOD_SIZE 8
#define PATH_SIZE 256
#define UA_SIZE 512
#define BACKLOG 5

/**
 * @brief A structure to hold all parsed request data.
 */
typedef struct {
    char method[METHOD_SIZE];
    char path[PATH_SIZE];
    char user_agent[UA_SIZE];
    int  error;  // Non-zero if an error occurred during parsing
} HttpRequest;

/**
 * @brief Holds data about a client connection passed to each thread.
 */
typedef struct {
    int fd;
} ClientData;

/**
 * @brief Reads and parses the HTTP request from the client socket (fd).
 *
 */
HttpRequest parse_http_request(int fd, char *response, size_t response_size)
{
    HttpRequest request;
    memset(&request, 0, sizeof(HttpRequest));

    int bytes_received = recv(fd, response, response_size - 1, 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "recv() error (%d): %s\n", bytes_received, strerror(errno));
        request.error = 1; 
        return request; 
    }
    response[bytes_received] = '\0';

    printf("Request:\r\n%s", response);

    char *line = strtok(response, "\r\n");
    if (!line) {
        fprintf(stderr, "No request line found.\n");
        request.error = 1;
        return request;
    }

    if (sscanf(line, "%7s %255s", request.method, request.path) != 2) {
        fprintf(stderr, "Failed to parse request line.\n");
        request.error = 1;
        return request;
    }

    // Parse headers
    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(line) == 0) {
            // End of headers
            break;
        }
        if (strncasecmp(line, "User-Agent:", 11) == 0) {
            const char *ua_start = line + 11;
            while (*ua_start == ' ' || *ua_start == '\t') {
                ua_start++;
            }
            strncpy(request.user_agent, ua_start, UA_SIZE - 1);
            request.user_agent[UA_SIZE - 1] = '\0';
        }
    }

    return request;  // .error = 0 if successful
}

/**
 * @brief Constructs an HTTP response based on the parsed HttpRequest data.
 *
 */
int build_http_response(const HttpRequest *req, char *response, size_t response_size)
{
    if (req->error) {
        snprintf(response, response_size,
                 "HTTP/1.1 400 Bad Request\r\n\r\n");
        return 0;
    }

    if (strcmp(req->method, "GET") != 0) {
        snprintf(response, response_size,
                 "HTTP/1.1 405 Method Not Allowed\r\n\r\n");
        return 0;
    }

    // /echo/{str}
    if (strncmp(req->path, "/echo/", 6) == 0) {
        const char *echo_str = req->path + 6;
        size_t echo_len = strlen(echo_str);

        int ret = snprintf(response, response_size,
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: %zu\r\n"
                           "\r\n"
                           "%s",
                           echo_len, echo_str);
        if (ret < 0 || (size_t)ret >= response_size) {
            fprintf(stderr, "Response truncation in /echo/.\n");
            return -1;
        }
        return 0;
    }
    // Root or /index
    else if (strcmp(req->path, "/") == 0 || strcmp(req->path, "/index") == 0) {
        snprintf(response, response_size, "HTTP/1.1 200 OK\r\n\r\n");
        return 0;
    }
    // /user-agent
    else if (strncmp(req->path, "/user-agent", 11) == 0) {
        size_t ua_len = strlen(req->user_agent);

        int ret = snprintf(response, response_size,
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: %zu\r\n"
                           "\r\n"
                           "%s",
                           ua_len, req->user_agent);
        if (ret < 0 || (size_t)ret >= response_size) {
            fprintf(stderr, "Response truncation in /user-agent.\n");
            return -1;
        }
        return 0;
    }
    // Unknown path -> 404
    else {
        snprintf(response, response_size,
                 "HTTP/1.1 404 Not Found\r\n\r\n");
        return 0;
    }
}

/**
 * @brief Thread function that handles a single client's request/response cycle.
 */
void* handle_client(void *arg)
{
    ClientData *client_data = (ClientData *)arg;
    int fd = client_data->fd;

    char response[BUFFER_SIZE];

    // 1) Parse
    HttpRequest req = parse_http_request(fd, response, sizeof(response));
    // 2) Build
    int build_result = build_http_response(&req, response, sizeof(response));
    // 3) Send
    if (build_result < 0) {
        printf("Failed to build HTTP response.\n");
    } else {
        int bytes_sent = send(fd, response, strlen(response), 0);
        if (bytes_sent == -1) {
            printf("Send failed: %s \n", strerror(errno));
        } else {
            printf("Response sent successfully.\n");
        }
    }

    close(fd);
    free(client_data);
    return NULL;
}

/**
 * @brief Sets up the server, listens for connections in a loop, 
 *        and spawns a new thread for each client.
 *
 * @param port The port number to listen on.
 * @return int 0 on success, -1 on failure.
 */
int setup_server(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        printf("Socket creation failed: %s...\n", strerror(errno));
        return -1;
    }

    // Reuse address
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        printf("SO_REUSEADDR failed: %s \n", strerror(errno));
        close(server_fd);
        return -1;
    }

    // Bind
    struct sockaddr_in serv_addr = { 
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr   = { htonl(INADDR_ANY) },
    };

    if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
        printf("Bind failed: %s \n", strerror(errno));
        close(server_fd);
        return -1;
    }

    // Listen
    if (listen(server_fd, BACKLOG) != 0) {
        printf("Listen failed: %s \n", strerror(errno));
        close(server_fd);
        return -1;
    }

    printf("Server listening on port %d...\n", port);

    // Main loop: accept new clients in separate threads
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        // Blocking accept
        int fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (fd < 0) {
            printf("Accept failed: %s\n", strerror(errno));
            break;  // or continue, depending on your preference
        }

        printf("Client connected (fd=%d)\n", fd);

        // Allocate a ClientData for this connection
        ClientData *client_data = (ClientData *)malloc(sizeof(ClientData));
        if (!client_data) {
            printf("Memory allocation failed.\n");
            close(fd);
            continue;
        }
        client_data->fd = fd;

        // Spawn a thread to handle the client
        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, client_data) != 0) {
            printf("Failed to create client thread: %s\n", strerror(errno));
            close(fd);
            free(client_data);
            continue;
        }
        // Detach so it cleans up on its own
        pthread_detach(tid);
    }

    // If we exit the loop, it means accept failed or some condition to stop
    printf("Server shutting down...\n");
    close(server_fd);
    return 0;
}

/**
 * @brief Main entry point
 */
int main() {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int port = 4221;
    if (setup_server(port) == -1) {
        printf("Failed to set up server.\n");
        return 1;
    }

    printf("Server closed.\n");
    return 0;
}

