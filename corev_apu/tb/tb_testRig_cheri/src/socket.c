#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

#include <socket.h>

#define SOCKET_NAME_STR_SIZE 256
#define SOCKET_INIT_FD -1
#define SOCKET_INIT_CONNECTION -1
#define SOCKET_MAX_CONNECTIONS 3

/** Returns true on success, or false if there was an error */
int setSocketBlockingMode(int fd, int blocking)
{
   int ret = -1;
   int flags = 0;
   if (fd < 0) return -1;
   flags = fcntl(fd, F_GETFL, 0);
   if (flags == -1) return -1;
   flags = (blocking == 1) ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
   ret = fcntl(fd, F_SETFL, flags);
   return ret;
}

static inline int acceptSocketServConnection(sock_serv_state_t* sock_state_ptr) {
    // Check if socket created
    if (sock_state_ptr == NULL)
        return -1;
    // Check connection and fd
    if (sock_state_ptr->fd < 0 || sock_state_ptr->conn > 0)
        return -1;
    // Accept connection
    sock_state_ptr->conn = accept(sock_state_ptr->fd, NULL, NULL); 
    // Make connection non-blocking
    // if (sock_state_ptr->conn != -1) {
    //     setSocketBlockingMode(sock_state_ptr->conn, 0);
    //     return 0;
    // }
    if (sock_state_ptr->conn == -1)
      return -1;
    else
      return 0;
}

sock_serv_state_t* initSocketServ(const char * socket_name, unsigned int default_socket_port) {
    struct sockaddr_in sock_address;
    sock_serv_state_t* sock_state_ptr = NULL;
    int sock_addrlen = sizeof(sock_address);
    int ret = 0;
    int opt = 1;
    // Fail if socket already initialized
    if (sock_state_ptr  != NULL) {
        fprintf(stderr, "ERROR: Socket already initialized ! \n");
        exit(EXIT_FAILURE);
    }
    // Initiliaze the socket
    sock_state_ptr = (sock_serv_state_t *) malloc(sizeof(sock_serv_state_t));
    if (strncpy(sock_state_ptr->name, socket_name, SOCKET_NAME_STR_SIZE) == NULL) {
        fprintf(stderr, "ERROR: Failed to copy socket name \n");
        exit(EXIT_FAILURE);
    }
    sock_state_ptr->port = default_socket_port;
    sock_state_ptr->fd = SOCKET_INIT_FD;
    sock_state_ptr->conn = SOCKET_INIT_CONNECTION;

    // Create socket file descriptor
    sock_state_ptr->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_state_ptr->fd < 0) {
        perror("ERROR: Failed to create socket! \r\n");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port
    if (setsockopt(sock_state_ptr->fd, SOL_SOCKET, SO_REUSEADDR, &opt,sizeof(opt)) < 0) {
        perror("ERROR: Unable to set reuseaddr on socket!");
        exit(EXIT_FAILURE);
    }
    // Operation Bind
    sock_state_ptr->addrlen = sizeof(sock_address);
    memset(&sock_state_ptr->address, 0, sock_state_ptr->addrlen);
    sock_state_ptr->address.sin_family = AF_INET;
    sock_state_ptr->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sock_state_ptr->address.sin_port = htons(sock_state_ptr->port);
    ret = bind(sock_state_ptr->fd, (struct sockaddr*)&sock_state_ptr->address, sizeof(sock_state_ptr->address));
    if (ret < 0) {
        perror("ERROR: bind failed ! \r\n");
        exit(EXIT_FAILURE);
    }
    // Start listen for connections
    if (listen(sock_state_ptr->fd, 1) < 0) {
        perror("ERROR: Listen failed ! \r\n");
        exit(EXIT_FAILURE);
    }

    sock_state_ptr->conn = accept(sock_state_ptr->fd, NULL, NULL); 
    if (sock_state_ptr->conn == -1)
    {
      perror("ERROR: Accept connection failed ! \r\n");
      exit(EXIT_FAILURE);
    }
    // Set socket in non-blocking mode
    // ret = setSocketBlockingMode(sock_state_ptr->fd, 0);
    // assume always true
    // if (ret < 0) {
    //     perror("ERROR: Setting socket in non-blocking mode");
    //     exit(EXIT_FAILURE);
    // }
    return sock_state_ptr;
}

// Non-blocking read of 8 bits
uint32_t get8SocketServ(sock_serv_state_t* sock_serv)
{ 
  uint8_t byte;
  if (sock_serv == NULL)
    return -1;

  if (acceptSocketServConnection(sock_serv) == -1) {
    perror("ERROR: Connection failed ! \r\n");
    exit(EXIT_FAILURE);
  }

  if (sock_serv->conn == -1) return -1;
  int n = read(sock_serv->conn, &byte, 1);
  if (n == 1)
    return (uint32_t) byte;
  else if (!(n == -1 && errno == EAGAIN)) {
    close(sock_serv->conn);
    sock_serv->conn = -1;
  }
  return -1;
}

// Non-blocking write of 8 bits
uint8_t put8SocketServ(sock_serv_state_t* sock_serv, uint8_t byte)
{
  if (sock_serv == NULL) {
    fprintf(stderr, "ERROR: Socket already initialized ! \n");
    exit(EXIT_FAILURE);
  }

  //if (acceptSocketServConnection(sock_serv) == -1) {
  //  perror("ERROR: Connection failed ! \r\n");
  //  exit(EXIT_FAILURE);
  //}

  if (sock_serv->conn == -1) return 0;
  int n = write(sock_serv->conn, &byte, 1);
  if (n == 1)
    return 1;
  //else if (!(n == -1 && errno == EAGAIN)) {
  //  close(sock_serv->conn);
  //  sock_serv->conn = -1;
  //}
  return 0;
}

// Try to read N bytes from socket, giving N+1 byte result. Bottom N
// bytes contain data and MSB is 0 if data is valid or non-zero if no
// data is available.  Non-blocking on N-byte boundaries.
void getNSocketServ(unsigned int* result, sock_serv_state_t* sock_serv, int nbytes)
{
  printf("trying to read  1\r\n");
  uint8_t* bytes = (uint8_t*) result;
  if (sock_serv == NULL) {
    perror("ERROR: socket not provided ! \r\n");
    exit(EXIT_FAILURE);
    return;
  }
  printf("trying to read \r\n");
  // if (acceptSocketServConnection(sock_serv) == -1) {
  //   perror("ERROR: Connection failed ! \r\n");
  //   exit(EXIT_FAILURE);
  // }
  // printf(" Accept connection socket: %d conn %d port %d \r\n", sock_serv->fd, sock_serv->conn, sock_serv->port);
  // if (sock_serv->conn == -1) {
  //   bytes[nbytes] = 0xff;
  //   return;
  // }
  int count = read(sock_serv->conn, bytes, nbytes);
  printf("count %d \r\n",count);
  printf("nbytes %d \r\n",nbytes);
  if (count == nbytes) {
    bytes[nbytes] = 0;
    return;
  }
  else if (count > 0) {
    // Use blocking reads to get remaining data
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock_serv->conn, &fds);
    while (count < nbytes) {
      int res = select(sock_serv->conn+1, &fds, NULL, NULL, NULL);
      assert(res >= 0);
      res = read(sock_serv->conn, &bytes[count], nbytes-count);
      assert(res >= 0);
      count += res;
      printf("count 1 %d \r\n",count);
    }
    bytes[nbytes] = 0;
    return;
  }
  else {
    bytes[nbytes] = 0xff;
    if (!(count == -1 && errno == EAGAIN)) {
      close(sock_serv->conn);
      sock_serv->conn = -1;
    }
    return;
  }
}

// Try to write N bytes to socket.  Non-blocking on N-bytes boundaries,
// returning 0 when no write performed.
uint8_t putNSocketServ(sock_serv_state_t* sock_serv, int nbytes, unsigned int* data)
{
  if (sock_serv == NULL) {
    fprintf(stderr, "ERROR: Socket already initialized ! \n");
    exit(EXIT_FAILURE);
  }

  // if (acceptSocketServConnection(sock_serv) == -1) {
  //   perror("ERROR: Connection failed ! \r\n");
  //   exit(EXIT_FAILURE);
  // }
  //if (sock_serv->conn == -1) return 0;
  uint8_t* bytes = (uint8_t*) data;
  int count = write(sock_serv->conn, bytes, nbytes);
  if (count == nbytes)
    return 1;
  else if (count > 0) {
    // Use blocking writes to put remaining data
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock_serv->conn, &fds);
    while (count < nbytes) {
      fflush(stdout);
      int res = select(sock_serv->conn+1, &fds, NULL, NULL, NULL);
      assert(res >= 0);
      res = write(sock_serv->conn, &bytes[count], nbytes-count);
      assert(res >= 0);
      count += res;
    }
    return 1;
  }
  else {
    if (!(count == -1 && errno == EAGAIN)) {
      close(sock_serv->conn);
      sock_serv->conn = -1;
    }
    return 0;
  }
}