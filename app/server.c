#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

// Constants
#define BUFFER_SIZE 1024
#define METHOD_SIZE 8
#define PATH_SIZE 256
#define BACKLOG 5

// Function Prototypes
int setup_server(int port);
int process_request(int fd, char *response, size_t response_size);

/**
 * @brief Sets up the server by creating, binding, listening, and accepting a connection.
 *
 * @param port The port number to listen on.
 * @return int The client socket file descriptor on success, -1 on failure.
 */
int setup_server(int port) {
  int server_fd;
  socklen_t client_addr_len;
  struct sockaddr_in client_addr;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return -1;
  }

  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    printf("SO_REUSEADDR failed: %s \n", strerror(errno));
    close(server_fd);
    return -1;
  }

  struct sockaddr_in serv_addr = { 
    .sin_family = AF_INET, // IPv4
    .sin_port = htons(port), //port: 4221
    .sin_addr = { htonl(INADDR_ANY) }, // Any IP available
  };

  if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    close(server_fd);
    return -1;
  }
  
  if (listen(server_fd, BACKLOG) != 0) {
    printf("Listen failed: %s \n", strerror(errno));
    close(server_fd);
    return -1;
  }

  printf("Waiting for a client to connect...\n");
  client_addr_len = sizeof(client_addr);

  int fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
  if (fd == -1) {
    printf("Accept failed: %s \n", strerror(errno));
    close(server_fd);
    return -1;
  }
  
  printf("Client connected\n");

  close(server_fd);
  return fd;
}


/**
 * @brief Receives an HTTP request from the client, parses the method and path, and sets the appropriate HTTP response.
 *
 * @param fd              The file descriptor for the connected client socket.
 * @param response        A buffer to store the generated HTTP response.
 * @param response_size   The size of the response buffer to prevent overflow.
 * @return int             Returns 0 on successful processing, -1 on failure.
 */
int process_request(int fd, char *response, size_t response_size) {
    // Receive the Request
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(fd, buffer, sizeof(buffer) - 1, 0);

    printf("Bytes received: %d\n", bytes_received); // Debug statement

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the received data

        // Parse the HTTP method and path
        char method[METHOD_SIZE];
        char path[PATH_SIZE];
        int sscanf_result = sscanf(buffer, "%7s %255s", method, path);

        printf("Method: %s, Path: %s\n", method, path); // Debug statement

        if (sscanf_result != 2) {
            printf("Failed to parse request.\n");
            return -1;
        }

        // Check if the request method is GET
        if (strcmp(method, "GET") != 0) {
            // Only handle GET requests; respond with 405 Method Not Allowed
            snprintf(response, response_size, "HTTP/1.1 405 Method Not Allowed\r\n\r\n");
            return 0;
        }

        // Handle the /echo/{str} endpoint
        if (strncmp(path, "/echo/", 6) == 0) {
            char *echo_str = path + 6; // Extract the string after "/echo/"
            size_t echo_len = strlen(echo_str);

            // Construct the HTTP response with headers
            int ret = snprintf(response, response_size,
                               "HTTP/1.1 200 OK\r\n"
                               "Content-Type: text/plain\r\n"
                               "Content-Length: %zu\r\n"
                               "\r\n"
                               "%s",
                               echo_len, echo_str);
            if (ret < 0 || (size_t)ret >= response_size) {
                printf("Failed to construct echo response.\n");
                return -1;
            }
            return 0;
        }
        // Handle the root (/) and /index endpoints
        else if (strcmp(path, "/") == 0 || strcmp(path, "/index") == 0) {
            snprintf(response, response_size, "HTTP/1.1 200 OK\r\n\r\n");
            return 0;
        }
        // Handle unknown endpoints
        else {
            snprintf(response, response_size, "HTTP/1.1 404 Not Found\r\n\r\n");
            return 0;
        }
    } else {
        printf("Recv returned %d: %s\n", bytes_received, strerror(errno)); // Debug statement
        return -1;
    }
    return 0;
}


int main() {
  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // Setup the Server
  int port = 4221;
  int fd = setup_server(port);
  if (fd == -1) {
    printf("Failed to set up server.\n");
    return 1;
  }

  // Process the client's request
  char response[BUFFER_SIZE];
  if (process_request(fd, response, sizeof(response)) == -1) {
      printf("Failed to process client request.\n");
      close(fd);
      return 1;
  }

  // Send response
  int bytes_sent = send(fd, response, strlen(response), 0);
  if (bytes_sent == -1){
      printf("Send failed: %s \n", strerror(errno));
      return 1;
  } else {
      printf("Response sent successfully.\n");
  }

  // Close Socket
  close(fd);
  return 0;
}

