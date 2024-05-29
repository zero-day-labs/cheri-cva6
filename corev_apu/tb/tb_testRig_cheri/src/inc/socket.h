#ifndef __SOCKET_H__
#define __SOCKET_H__

#ifdef __cplusplus
extern "C" {
#endif
    #include <stdint.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #define SOCKET_NAME_STR_SIZE 256
    #define SOCKET_INIT_FD -1
    #define SOCKET_INIT_CONNECTION -1
    #define SOCKET_MAX_CONNECTIONS 3

    typedef struct sock_serv_state_t{
        char name[SOCKET_NAME_STR_SIZE];
        int port;
        int fd;
        int conn;
        struct sockaddr_in address;
        socklen_t addrlen;
    } sock_serv_state_t;

    sock_serv_state_t* initSocketServ(const char * socket_name, unsigned int default_socket_port);
    uint32_t get8SocketServ(sock_serv_state_t* sock_serv);
    uint8_t put8SocketServ(sock_serv_state_t* sock_serv, uint8_t byte);
    void getNSocketServ(unsigned int* result, sock_serv_state_t* sock_serv, int nbytes);
    uint8_t putNSocketServ(sock_serv_state_t* sock_serv, int nbytes, unsigned int* data);

#ifdef __cplusplus
}
#endif

#endif