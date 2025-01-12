#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

// Constants
#define BUFFER_SIZE 1024
#define METHOD_SIZE 8
#define PATH_SIZE   256
#define HEADER_SIZE 512
#define BACKLOG     5

/**
 * @brief A structure to hold all parsed request data.
 */
typedef struct {
  char method[METHOD_SIZE];
  char path[PATH_SIZE];
  char user_agent[HEADER_SIZE];
  char content_type[HEADER_SIZE];
  char accept_encoding[HEADER_SIZE];

  int  content_length;
  char body[BUFFER_SIZE];

  char file_path[PATH_SIZE];
  int  error;  // Non-zero if an error occurred during parsing
} HttpRequest;

/**
 * @brief Holds data about a client connection passed to each thread.
 */
typedef struct {
  int  fd;
  char file_path[PATH_SIZE];
} ClientData;

/**
 * @brief Reads and parses the HTTP request from the client socket (fd).
 */
HttpRequest parse_http_request(ClientData *client_data, char *response,
                               size_t response_size)
{
  HttpRequest request;
  memset(&request, 0, sizeof(HttpRequest));

  // 1) Read the first chunk (headers + possibly some/all of the body)
  int bytes_received = recv(client_data->fd, response, response_size - 1, 0);
  if (bytes_received <= 0) {
    fprintf(stderr, "recv() error (%d): %s\n", bytes_received, strerror(errno));
    request.error = 1;
    return request;
  }
  // Null-terminate for safe string ops
  response[bytes_received] = '\0';

  printf("Request:\r\n%s\r\n", response);

  // 2) Locate the blank line that marks end of headers
  char *body_start_ptr = strstr(response, "\r\n\r\n");
  int body_in_buffer = 0;

  if (body_start_ptr) {
    *body_start_ptr       = '\0';
    *(body_start_ptr + 1) = '\0';
    *(body_start_ptr + 2) = '\0';
    *(body_start_ptr + 3) = '\0';

    body_start_ptr += 4;

    body_in_buffer = bytes_received - (int)(body_start_ptr - response);
    if (body_in_buffer > 0) {
      memcpy(request.body, body_start_ptr, body_in_buffer);
      request.body[body_in_buffer] = '\0';
    }
  }

  // 3) Parse the request line
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

  // 4) Parse headers line by line
  while ((line = strtok(NULL, "\r\n")) != NULL) {
    if (strncasecmp(line, "Content-Length:", 15) == 0) {
      const char *cl_start = line + 15;
      while (*cl_start == ' ' || *cl_start == '\t') {
        cl_start++;
      }
      request.content_length = atoi(cl_start);
    }
    else if (strncasecmp(line, "User-Agent:", 11) == 0) {
      const char *ua_start = line + 11;
      while (*ua_start == ' ' || *ua_start == '\t') {
        ua_start++;
      }
      strncpy(request.user_agent, ua_start, HEADER_SIZE - 1);
      request.user_agent[HEADER_SIZE - 1] = '\0';
    }
    else if (strncasecmp(line, "Content-Type:", 13) == 0) {
      const char *ct_start = line + 13;
      while (*ct_start == ' ' || *ct_start == '\t') {
        ct_start++;
      }
      strncpy(request.content_type, ct_start, HEADER_SIZE - 1);
      request.content_type[HEADER_SIZE - 1] = '\0';
    }
    else if (strncasecmp(line, "Accept-Encoding:", 16) == 0) {
      const char *encoding = line + 16;
      while (*encoding == ' ' || *encoding == '\t') {
        encoding++;
      }
      strncpy(request.accept_encoding, encoding, HEADER_SIZE - 1);
      request.accept_encoding[HEADER_SIZE - 1] = '\0';
    }

    // If path starts with /files/, store the filename in request.file_path
    if (strncmp(request.path, "/files/", 7) == 0) {
      const char *file_name = request.path + 7;
      strncpy(request.file_path, file_name, sizeof(request.file_path) - 1);
      request.file_path[sizeof(request.file_path) - 1] = '\0';
    }
  }

  // 5) Read remaining body if needed
  if (request.content_length > body_in_buffer) {
    int still_needed = request.content_length - body_in_buffer;
    int extra_bytes  = recv(client_data->fd,
                            request.body + body_in_buffer,
                            still_needed, 0);
    if (extra_bytes > 0) {
      body_in_buffer += extra_bytes;
      request.body[body_in_buffer] = '\0';
    }
    else {
      request.error = 1;
    }
  }

  return request;
}

/* 
 * ==========================================================================
 *                       RESPONSE HANDLER FUNCTIONS
 * ==========================================================================
 * Below, there are small functions that handle specific routes.
 * They build the HTTP response string and return an int.
 * Return 0 means success, non-zero could indicate an error.
 */

/**
 * @brief Sends an HTTP 400 response.
 */
static int handle_bad_request(char *response, size_t response_size) {
  snprintf(response, response_size, "HTTP/1.1 400 Bad Request\r\n\r\n");
  return 0;
}

/**
 * @brief Sends an HTTP 405 response.
 */
static int handle_method_not_allowed(char *response, size_t response_size) {
  snprintf(response, response_size, "HTTP/1.1 405 Method Not Allowed\r\n\r\n");
  return 0;
}

/**
 * @brief Sends an HTTP 404 response.
 */
static int handle_not_found(char *response, size_t response_size) {
  snprintf(response, response_size, "HTTP/1.1 404 Not Found\r\n\r\n");
  return 0;
}

/**
 * @brief Handles /echo/ route (GET).
 */
static int handle_echo(const HttpRequest *req, char *response, size_t response_size) {
  const char *echo_str = req->path + 6; // skip "/echo/"
  size_t echo_len = strlen(echo_str);
  if (strcmp(req->accept_encoding, "gzip") != 0) {
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
  } else {
    int ret = snprintf(response, response_size,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Encoding: %s\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n"
                     "%s",
                     req->accept_encoding,echo_len, echo_str);
    if (ret < 0 || (size_t)ret >= response_size) {
      fprintf(stderr, "Response truncation in /echo/.\n");
      return -1;
    }
  }
    return 0;
}

/**
 * @brief Handles GET /files/<filename>
 */
static int handle_files_get(ClientData *client_data, const HttpRequest *req,
                            char *response, size_t response_size)
{
  // Construct the file path
  char file_path[PATH_SIZE];
  snprintf(file_path, sizeof(file_path), "%s%s",
           client_data->file_path, req->file_path);
  printf("Filepath: %s\n", file_path);

  FILE *file = fopen(file_path, "r");
  if (file == NULL) {
    perror("Error opening file");
    snprintf(response, response_size, "HTTP/1.1 404 Not Found\r\n\r\n");
    return 1;
  }

  // For simplicity, read up to one line and send it back
  char buffer[256];
  if (fgets(buffer, sizeof(buffer), file)) {
    size_t file_len = strlen(buffer);
    int ret = snprintf(response, response_size,
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/octet-stream\r\n"
                       "Content-Length: %zu\r\n"
                       "\r\n"
                       "%s",
                       file_len, buffer);
    if (ret < 0 || (size_t)ret >= response_size) {
      fprintf(stderr, "Response truncation in /files/.\n");
      fclose(file);
      return -1;
    }
  } else {
    // File is empty or read error
    snprintf(response, response_size,
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/octet-stream\r\n"
             "Content-Length: 0\r\n"
             "\r\n");
  }
  fclose(file);
  return 0;
}

/**
 * @brief Handles POST /files/<filename>
 */
static int handle_files_post(ClientData *client_data, const HttpRequest *req,
                             char *response, size_t response_size)
{
  // Construct the file path
  char file_path[PATH_SIZE];
  snprintf(file_path, sizeof(file_path), "%s%s",
           client_data->file_path, req->file_path);
  printf("Writing file: %s\n", file_path);

  FILE *file = fopen(file_path, "w");
  if (!file) {
    perror("Error opening file");
    snprintf(response, response_size, "HTTP/1.1 500 Not Found\r\n\r\n");
    return 1;
  }

  size_t bytes_written = fwrite(req->body, 1, req->content_length, file);
  if (bytes_written < (size_t)req->content_length) {
    perror("Error writing to file");
    fclose(file);
    snprintf(response, response_size, "HTTP/1.1 500 Internal Server Error\r\n\r\n");
    return 1;
  }
  fclose(file);
  snprintf(response, response_size, "HTTP/1.1 201 Created\r\n\r\n");
  return 0;
}

/**
 * @brief Handles / (root) or /index
 */
static int handle_root_index(char *response, size_t response_size)
{
  snprintf(response, response_size, "HTTP/1.1 200 OK\r\n\r\n");
  return 0;
}

/**
 * @brief Handles /user-agent
 */
static int handle_user_agent(const HttpRequest *req, char *response, size_t response_size)
{
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

/**
 * @brief Constructs an HTTP response based on the parsed HttpRequest data.
 */
int build_http_response(ClientData *client_data, const HttpRequest *req,
                        char *response, size_t response_size)
{
  // 1) Check for early errors
  if (req->error) {
    return handle_bad_request(response, response_size);
  }

  // 2) Check if method is allowed
  if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "POST") != 0) {
    return handle_method_not_allowed(response, response_size);
  }

  // 3) Route by path + method
  if (strcmp(req->path, "/") == 0 || strcmp(req->path, "/index") == 0) {
    return handle_root_index(response, response_size);
  }
  else if (strncmp(req->path, "/echo/", 6) == 0 && strcmp(req->method, "GET") == 0) {
    return handle_echo(req, response, response_size);
  }
  else if (strncmp(req->path, "/user-agent", 11) == 0 && strcmp(req->method, "GET") == 0) {
    return handle_user_agent(req, response, response_size);
  }
  else if (strncmp(req->path, "/files/", 7) == 0) {
    // We have two possible methods: GET or POST
    if (strcmp(req->method, "GET") == 0) {
      return handle_files_get(client_data, req, response, response_size);
    } else if (strcmp(req->method, "POST") == 0) {
      return handle_files_post(client_data, req, response, response_size);
    }
  }

  // 4) If nothing matched, 404
  return handle_not_found(response, response_size);
}

/**
 * @brief Thread function that handles a single client's request/response cycle.
 */
void *handle_client(void *arg)
{
  ClientData *client_data = (ClientData *)arg;

  char response[BUFFER_SIZE];

  // 1) Parse
  HttpRequest req = parse_http_request(client_data, response, sizeof(response));

  // 2) Build
  int build_result = build_http_response(client_data, &req,
                                         response, sizeof(response));

  // 3) Send
  if (build_result < 0) {
    printf("Failed to build HTTP response.\n");
  } else {
    int bytes_sent = send(client_data->fd, response, strlen(response), 0);
    if (bytes_sent == -1) {
      printf("Send failed: %s \n", strerror(errno));
    } else {
      printf("Response sent successfully.\n");
    }
  }

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
int setup_server(int port, char *filepath) {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return -1;
  }

  // Reuse address
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                 &reuse, sizeof(reuse)) < 0) {
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

  if (bind(server_fd, (struct sockaddr *) &serv_addr,
           sizeof(serv_addr)) != 0) {
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
    ClientData *client_data = malloc(sizeof(ClientData));
    if (!client_data) {
      printf("Memory allocation failed.\n");
      close(fd);
      continue;
    }
    client_data->fd = fd;
    strcpy(client_data->file_path, filepath);

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
int main(int argc, char *argv[]) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  char filepath[PATH_SIZE] = {0};  // buffer for the directory path

  // If you expect at least one CLI arg, handle it
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--directory") == 0 && i + 1 < argc) {
      snprintf(filepath, sizeof(filepath), "%s", argv[i + 1]);
      printf("This is the filepath stored: %s\n", filepath);
    }
  }

  int port = 4221;
  if (setup_server(port, filepath) == -1) {
    printf("Failed to set up server.\n");
    return 1;
  }

  printf("Server closed.\n");
  return 0;
}

