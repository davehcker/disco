# 1. Introduction to Network Programming
## Introduction
Programming systems communicating across a computer network requires, at the very least, that the information sent across is *understood* by the parties involved. We might also be concerned about guaranteeing that the transfer of information was successful, transfer-rate, security, etc. To achieve the former goal, we need a set of mutually understood rules, *protocols*. We can extend the idea of protocols across all the layers of communication involved and that multiple protocols may apply to a *packet* of information before it is delivered (and understood) by the receiver. Choosing the correct protocols is the first step in programming networking applications.      
A Web Server is typically thought of as a long-running programs (or *daemon*) that sends netwok messages only in response to requests coming in from the network. The other side is a *client* which always initiates the communication.       
The **Internet** is the largest *WAN (Wide Area Network)* today, which can be crudely defined as a massive collection of *LANs (Local Area Network)* connected to each other via routers.           
## Programming a Simple Daytime Client
Here we describe the pseudo-code (for C) to program a simple *daytime* client. Next, we'll also program a server, which can be thought of as a 'special client'.

```
int main(int argc, char **argv){
        int sockfd, n;
        char recvline[MAXLINE+1];
        struct sockaddr_in servaddr;
        
        /*1. CREATE a TCP socket*/
        if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            //signal socket error
            }
        
        /*Set the socket address with IP address and port number */
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servadd.sin_port = htons(13);
        // set the servaddr.sin_addr.
        
        /*2. CONNECT the socket*/
        if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0){
            //raise connect erro 
            
        /*3. READ the socket*/
        //The final step is to read from the socket. A common style is to
        // read in a loop till EOF is detected.
        While(( n = read(sockfd, recvline, MAXLINE)) > 0)...
        
        exit(0);
        
    }

```
**Create a TCP Socket** The `socket` function creates an Internet(`AF_INET`)stream (`SOCK STREAM`) socket i.e. a TCP socket. More on the constants a bit later. The function returns an integer descriptor to identify the socket for future function calls.      
**Read and Display the server's reply** Normally, a single segment containg all the bytes returned, but with larger data sizes, we cannot always assume the reply to be returned by a single `read`. Therefore, reading from a TCP socket, we *always* need to code the `read` in a loop.
**Terminate the program** `exit` terminates the program. UNIX will always close all the open descriptors when a process terminates, so our TCP socket is now closed.
**NOTE: Protocol Independencs** The program we have written above works only with IPv4, and will not work with a system using IPv6. Of course, there are ways to write protocol independent code, and it is recommended too.
**NOTE: Wrapper Functions** Because so much of the code in practice will be repetitive (for example error handlig for various calls), it is good to have wrapper functions in place.

## A Simple Daytime Server
The program for the server is very similar to the client program, the pseudo-code below points out the differences and the main steps:
```
int main(int argc, char **argv){
    //declarations.
    
    /* 1. CREATE the Socket */
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    
    //define the socket i.e sockaddr_in serveaddr.
    
    /* 2. BIND the socket */
    bind(listenfd, (struct sockaddr *), sizeof(sockaddr));
    
    /* 3. LISTEN */
    listen(listenfd, LISTENQ i.e. max no. of connection to queue);
    
    /* 4. ACCEPT connections and 5. READ the socket */
    for (; ;){
        int connfd = accept(listenfd, (struct sockaddr *) NULL, NULL);
        // play with connfd.
        
        /* 5. TERMINATE connection */
        close(connfd);
    }
}
````
**Create a TCP socket** Notice that it's same as client's socket code.
**Bind step** Binds the servers port to the socket by filling the Internet socket address structure and calling `bind`. The IP address of the setver can be set in a way to differentiate the interace on which the server listens to client connections. `INADDR_ANY` allows the server to accept a client connection on any interface.        
**Convert socket to listening socket** By calling `listen`, the socket is converted into a listening socket, on which incoming connection from clients will be accepted by the kernel. These three steps, `socket`, `bind`, and `listen` are the normal steps for any TCP server to prepare what we call the *listening descriptor* (`listenfd` in the example).            
**Accept client connection, send reply** A TCP connection uses what is called a *three-way handshake* to establish a connection. When this handshake completes, `accept` returns, and the return value is the new descriptor, called the *connected descriptor*.          
**Terminate Coonection** The server closes the connection by calling `close`: a FIN is sent in each direction and each FIN is acknowledged by the other end.         
**NOTE: Iterative and concurrent server** The server that we have programmed above is an iterative one in that it iterates through each client at a time. Generally, we need a concurrent server that is capable of handling multiple clients at the same time.         
**NOTE: This was just an overview.**

## Open Systems Interconnection (OSI) Model and a bit of Useful Theory
| OSI Layers  | IP Suite  |
|:-:|:---:|
|  7. Application | Applicatton   |
|  6. Presentation | -  |
|  5. Session | -  |
| [sockets are here]  | [sockets are here]  |
|  4. Transport | TCP/UDP/* |
|  3. Network | IPv4, IPv6 |
|  2. Datalink | device driver and hardware  |
|  1. Physical | - |       
Corresponding to layer 4 of OSI, the asterisk is for *raw sockets* that can bypass the transport layer and use IPv4 or IPv6 directly.       
The socket programming described here lie in the domain of first three layers. Our main focus is to write applications using TCP/ UDP sockets. There are two main reasons why sockets sit in the stack where they are:        
- The first three layers are all about the application, and know little about the communication details. Similarly, the lower four layers know little about the application, and rather handle all the communication services.
- The uppper three layers often form *user process* whereas the lower four layers are provided as the the part of OS kernel.

## Testing Networks and Hosts ##
`netstat` and `ifconfig` are two basic network tools that can be used on UNIX systems. Here's a list of handy commands to get started: 
- `netstat -i` provides information on interfaces.      
- `netstat -r` shows the routing table. `-n` flag prints the numeric addresses.
- `ifconfig [interfaceName]` given an interface name, we can obtain the details for it using *ifconfing*.
- Discover the hosts on the LAN by pinging to the local broadcast address as `ping -b [broadcastAddress]`
____
# 2. The Transport Layer: TCP, UDP, and SCTP
## The Big Picture
**IPv4** Uses 32-bit address, and provides packet delivery service for TCP, UDP, SCTP, ICMP, and IGMP.  

**IGMP** *Internet Group Management Protocol.* Used for multicasting, which is optional with IPv4.      

**ARP** *Address Resolution Protocol.* maps an IPv4 address into a hardware address.       

**RARP** *Reverse Address Resolution Protocol.* maps a hardware address into an IPv4 address. (eg diskless node booting.)       

**IPv6** Uses 128 bits, and provides packet delivery service for TCP, UDP, SCTP, ICMP, and IGMP.    

**ICMPv6** *Internet Control Message Protocol version 6.* combines the functionality of ICMPv4, IGMP, and ARP.       

**TCP** *Transmission Control Protocol.* TCP is a ***connection-oriented*** protocol that provides a reliable, ***full-duplex byte stream*** to its users. TCP sockets are an example of *stream sockets*. TCP also provides reliability with features like acknowledgements, timeouts, retransmissions, and the like. To provide ***reliability***, when TCP sends a packet, it requires an acknowledgement in return. If the acknowledgement is not received, TCP automatically retransmits the data and wait for longer time. TCP contains algorithm to estimate the ***round-trip time (RTT)*** between a client and server dynamically so that it knows how long to wait for acknowledgement. TCP also ***sequences*** the data by associating a sequence number with every byte that it sends. It also provides ***flow control***. TCP always tells its peer exactly how many bytes of data it is willing to accept from the peer at any one time, advertised as *window*.      

**UDP** *User Datagram Protocol.* UDP is a connectionless protocol, and UDP sockets are an example of *datagram sockets* There is no guarantee that UDP datagrams will ever reach their intended destination. The application writes a packet in a UDP *datagram* which is then encapsulated as an IP datagram, and then sent to the destination. If we want to be certain that a datagram reaches its destination, we will have be develop those features for our applications, since reliability services like ACK, timeouts, retransmission are not provided by UDP.        

**SCTP** *Stream Control Transmission Protocol.* SCTP is a connection-oriented protocol that provides a ***relieable full-duplex association***. Also, it can use both IPv4 and IPv6 simulataneously. Like UDP, the lenght of the record written is also passed. It can provide multiple streams between connection end-points, each with its own reliable ***sequence delivery***.       

**ICMP** *Internet Control Message Protocol.* ICMP handles error and control information between routers and hosts. These messages are normally generated by and processed by the TCP/IP netwroking software itself, not user processes.       
[Streams and Datagram Sockets](http://stackoverflow.com/questions/4688855/whats-the-difference-between-streams-and-datagrams-in-network-programming)

## TCP Connection Establishment and Termination
**Three-Way Handshake**: The following scenario occurs when a TCP connection is established:
1. The server must be *passively open* and listening. [Server State (Ss): LISTEN]
2. The client issues an *active-open* by calling `connect`. This causes the client TCP to send SYN segment, along with intial sequence number for data that will be sent. [Client State (Cs): SYN_SENT]
3. The sever ACKs the client's SYN and it also sends its initial sequence number for the data that the server will send. [Ss: SYN_RCVD]
4. Finally, the client must accept the server's SYN. [Cs: ESTABLISHED; Ss: ESTABLISHED]   

Because the total number of packets sent is at least three, hence the name.      
**TCP Connection Termination**: It takes four packets to terminate a connection. This is how it's executed:
1. The end performing *active close* calls `close`. This end's TCP sends a FIN segment, which means finished sending data. [Cs: FIN_WAIT_1]
2. The end that receives the FIN performs *passive close*. The receipt of FIN is also passed to the application as an EOF (actually appended to the current TCP buffer), since the receipt itself means that the application will not receive any additional data on the connection. [Ss: CLOSE_WAIT; Cs: FIN_WAIT_2]
3. When the other application that receives EOF will `close` its socket. This causes the TCP to send FIN. [Cs: TIME_WAIT]
4. The *active close* end now acknowledges the FIN. [Cs: TIME_WAIT; Ss: CLOSED]        

**BONUS:** ACK of any TCP command has a sequence number one more than of the command ACKed.

**NOTE: TCP Options** Commonly used TCP options are:
- *MSS* option is used by TCP sending the SYN to announce its *maximum segment size*. Sending TCP uses the receiver's MSS value as the maximum size of the segment it sends.
- *Window scale option*.
- *Timestamp option*. This option is needed for high-speed connections to prevent possible data corruption caused by old, delayed, or duplicated segments.

**ASIDE: TIME_WAIT State** The duration of this state is twice the *maximum segment lifetime (MSL)* and is important for two reasons: 
1. To impelement TCP's full-duplex connection reliably.
2. Two allow old duplicate segments to expire in a network. (hint: think of connection reincarnations and lost old packets.

# Sockets Introduction
## Socket Address Structures
Most socket functions require a pointer to a socket address structure as an argument. The names of these structures begine with sockaddr_ and end with a unique suffix for each protocol suite.       
**IPv4 Socket Address Structure:**       
Commonly known as "Internet socket address structure", as named `sockaddr_in` and is defined in the header `<netinet/in.h>`. Following is the POSIX definition.
```
struct in_addr{
    in_addr_t s_addr;  /*32-bit IPv4 network ordered address */
    };
    
struct sockaddr_in{
    unint8_t        sin_len;        /*length of structure (16) */
    sa_family_t     sin_family;     /*AF_INET*/
    in_port_t       sin_port;       /*16-bit TCP or UDP port number */
                                    /*network byte ordered */
    struct in_addr  sin_addr;       /*32-bit IPv4 address */
                                    /*network byte ordered */
    char            sine_zero[8];   /*unused; for proper alignment*/
```
**NOTE:** Socket address structure are used only on a given host: the structure itself is not communicated between different hosts.       
**ASIDE:** The `sin_zero` member is always set to 0. By convention, before filling, we set the whole structure to 0. Although most uses of the structure do not require that this member be 0, when binging wildcard IPv4 address, this must be 0.        
**Generic Socket Address Structure:**    
A socket address is *always* passed by reference to any socket function. But any socket function that takes one of these pointers as an argument must deal with socket address structures from any of the supported protocol families. Because the socket functions predate ANSI C, `void *` won't work. To deal with the problem, a *generic* socket address structure was defined in the `<sys/socket.h>` header, which is as follows. 
```
struct sockaddr {
    unin8_t     sa_len;
    sa_family_t sa_family;      /*address family: AF_xxx value*/
    char        sa_data[14];    /*protocol-specific address */
};
```
Thus, a correct call to `bind` function would become:      
```
strcut sockaddr_in serv;
bind(sockfd, (struct sockaddr *) &serv, sizeof(serv));
```

## Value-Result Arguments (Programming: Aside)
In C programming language, all the arguments are passed by value. In certain cases, however, it is useful to call functions by reference. In network programming the latter case is often used in the form of a paradigm called *value-result arguments*. The value result argument style comes in very handy when a variable is supposed to serve both the purposes. 
Consider, for example, the functions `bind`, `connect`, and `sendto` that have first argument a pointer to a socket address structure, and another argument is an integer for the size of the structure. These functions go from the process to the kernel. On the other hand, the function `accept`, `recvfrom`, `getsockname`, and `getpeername`, effectively work in the reverse direction. They pass the socket address strucutre from the kernel to the process. In this case both the arguments- the pointer to the socket structure, and the pointer to the size are pointers. The reason for sending size as pointer is: 1. *As a value*. It tells the kernel the size of the pointer so no data is written beyond the structure memory. 2. *As a result*. Through the size variable, the kernel tells the process how much data the kernel actually wrote in the structure.   

## Byte-Ordering Functions
Numeric information in binary form can be store in two byte orders known as *host byte order*: *little endian* or *big endian*. Because there is no standard for the byte orderings, networking programs should handle the byte ordering in their implementation. Luckily, C provides us with functions that handle the byte ordering for us. 
```
#include <netinet/in.h>
/*Host byte order to network byte order.*/
unint16_t htons(unint16_t host16bitvalue);
unint32_t htonl(unint32_t host32bitvalue);

/*Network byte order to host byte order.*/
unint 16_t ntohs(unint16_t net16bitvalue);
unint 32_t ntohl(unint32_t net32bitvalue);
```
We don't need to know the exact host byte order, just calling the above functions will handle it. It's always a good practice to use them wherever required becuase we never know on what host our code will be used.
**Asize:** Unlike host-byte order which is not standardized, network-byte order is always big-endian.

## Byte Manipulation Functions
C (ANSI) provides multiple functions to help us perform byte value manipulation. The functions below is one such short list of functions that always come in handy when writing network applications.
```
#includes <strings.h>

//sets the nbytes pointed by dest to zero.
void bzero(void *dest, size_t nbytes);

//copies nbytes from src to dest.//Handles overlaps properly
void bcopy(const void *src, void *dest, size_t nbytes);

//copies nbytes from src to dest.//Use memmove instead to handle overlaps.
void memcpy(void *dst, const void *src, size_t nbytes);

//compares n bytes pointed by the addresses ptr1, and ptr2.
int bcmp(const void *ptr1, const void *ptr2, size_t nbytes
//returns 0 if equal, non-zero otherwise.

//compares nbytes pointed to by the addresses ptr1, and ptr2.
//check details to see how it is different from bcmp.
int memcmp(const void *ptr1, const void *ptr2, size_t nbytes);
//return 0 if equal, <0 or >0 otherwise.
```

## `inet_pton` and `inet_ntop` Functions
In network applications, we onften need to convert back and forth between network and ascii representation of IP addresses. Following are the most used functions.
```
#include <arpa/inet.h>
//converts ascii representation into network-byte address.
int inet_aton(const char *strptr, struct in_addr *addptr);
//returns 1 if the string was valid, 0 on error.

//converts from network bytes to ascii representation.
char *inet_ntoa(struct in_addr inaddr);
//returns pointer to dotted-decimal string.
```

## `inet_pton` and `inet_ntop`
These two functions are more generic than the last two functions and can be used for both IPv4 and IPv6. The letters 'p' and 'n' stand for *presentation* and *numeric*.

```
#include <arpa/inet.h>
int inet_pton(int family, const char *strptr, void *addrptr);
//returns 1 if OK, 0 if input is not valid, -1 on error.

const char *inet_ntop(int family, const void *addrptr, char *strptr, size_t len);
//pointer to result if OK, NULL on error.
```
**Tip:** Note how `inet_pton` returns the value in to a pointer. We can easily write a wrapper function which can make our code protocol independent by taking in a pointer to the socket structure and checking the protocol family and setting the value of the required address structure as the return value of `inte_pton`.

## Dealing with `read` and `write` Functions
Stream sockets (e.g, TCP sockets) exhibit a behavior with the `read` and `write` functions that differs from normal file I/O. A `read` or `write` on a stream socket might input or output fewer bytes than requested, but this is not an error condition. The reason is that the buffer limits might be reached for the socket in the kernel. All that is required is to input or output the remaining bytes is for the caller to invoke the `read` or `write` function again.         
Thus, it is almost always necessary to read from inside a loop until we get all the input characters. A better idea is to write our own function `readn`, `writen`, `readline`, and the like and call them whenever we want to read or write. It is not unusual to find them in most of the network application. 
____
# Elementary TCP Sockets
### `socket` Function
To perform network I/O, the first thing a process must do is call the `socket` function, specifying the type of communication protocol desired.
```
#include <sys/socket.h>
int socket( int family, int type, int protocol);
// Returns: non-negative socket descriptor if OK, -1 on error.
```
Protocol *family* for `socket` function:
| **family/ domain** | **Description** |
|:------------:|:----------------|
|AF_INET| IPv4 Protocols|
|AF_INET6| IPv6 Protocols|
|AF_LOCAL| Unix domain protocols. |
|AF_ROUTE| Routing sockets. |
|AF_KEY | Key socket. |

*type* of socket for socket functions:
| **family/ domain** | **Description** |
|:------------:|:----------------|
|SOCK_STREAM| Stream socket |
|SOCK_DGRAM| Datagram socket |
|SOCK_SEQPACKET| Sequenced packet socket |
|SOCK_RAW| Raw socket |

*type* of socket for socket functions:
| **family/ domain** | **Description** |
|:------------:|:----------------|
|SOCK_STREAM| Stream socket |
|SOCK_DGRAM| Datagram socket |
|SOCK_SEQPACKET| Sequenced packet socket |
|SOCK_RAW| Raw socket |

*protocol* of sockets for socket functions:
| **family/ domain** | **Description** |
|:------------:|:----------------|
|IPPROTO_TCP| TCP transport protocol |
|IPPROTO_UDP| UDP transport protocol |
|IPPROTO_SCTP| SCTP transport protocol |
| 0 | Uses the applicable protocol. |

**Aside:** On success, the `socket` function returns a small non-negative integer value, similar to a file descriptor. Notice that to obtain this socket descriptor, all we have specified is a protocol family and the socket type. We have not yet specified either the local protocol address or the foreign protocol address.

### `connect` Function
`connect` function is used by a TCP client to establish a connection **with a TCP server**.
```
#include <sys/socket.h>
int connect(int sockfd, const struct socaddr *servaddr, socklen_t addrlen);
// Returns: 0 if OK, -1 on error
```
The socket structure must contain the IP address and port number of the server. The `connect` function initiates TCP's three way handshake and returns only when the connection is established or an error occurs.
Possible errors are:      
ESTIMEDOUT if the client receives no response to its SYN segment.       
ECONNREFUSED if no process is listening on the designated port specified.
ENETUNREACH/ EHOSTUNREAH ICMP respone of "not reachable" from some intermediate router.
**Aside:** The client doesn't have to call `bind`(see below) before calling `connect`. The kernel will choose both an ephermeral port and the source IP address if necessary.

### `bind` Function
The `bind` function assigns a local protocol address to a socket. With IP protocols, the protocol address is the combination of either a 32-bit IPv$ address or a 128-bit IPv6 address, along with a 16-bit TCP or UDP port.
```
#include <sys/socket.h>
int bind( int sockfd, cont struct sockaddr *myaddr, socklen_t addrlen);
// Returns: 0 if OK, -1 on error.
```
If the server doesn't bind a well-known port when started, the kernel will choose and ephemeral port, which might not what one would want with a TCP server as they are known by their well-known ports.
**Aside:** To obtain the value of the ephermeral port assigned by the kernel, we must call `getsockname` to return the protocol address. Why can't we get the assigned port from the pointer to the socket passed?

### `listen` Function
```
#include <sys/socket.h>
int listen( int sockfd, int backlog);
```
 
The `listen` function is called only by a TCP server and it performs two actions:
1. When a socket is create by the `socket` function, it is an active socket; issuing `listen` funcion converts an unconnected socket into a passive socket, indicating that the kernel should accept incoming connection requests directed to this socket.
2. The second argument is the specified number of connections the kernel should queue. There are two types of queues maintained by the kernel- *incomplete connection queue* (sockets have SYN_RCVD state) and *completed connection queue* (sockets have ESTABLISHED state). When `accept` is called, the first entry on the completed queue is returned to the process, if the queue is empty, the process is put to sleep until an entry is placed onto the completed queue.


**Aside:** It is always acceptable to to specify the backlog value larger than the kernel, the kernerl shoud silently truncate the value without returning an error. Another fool-proof method would be to set the backlog value as the environment variable LISTENQ. Call getenv("LISTENQ").
**Note:** The same backlog values may have different effect on different systems. It's not standardized.
### `accept` Function
`accept` is called by a TCP server to return the next completed connection from the front of the completed queue. If the completed connection queue is empty, the process is put to sleep.
```
#include <sys/socket.h>
int accept(int sockfd, struct sockaddr *cliaddr, socklen_t *addrlen);
// Returns: non-negative descriptor if OK, -1 on error.
```
Notice that we pass the variable *sockfd*, it refers to the socket that we previously created and then bind. If the the call to `accept` is successful, we will refer to the socket as *connected socket*. Also, here again, we are using value-result paradigm when passing the pointer and size to the socket structure address.
### `fork` and `exec` Functions.
Calling `fork` is the only way to to create a new process in Unix. It is called once, but returns twice, 0 in the child process, and child pid in the parent process. The reason parent's pid is not sent to the child because it is always available to the child and can be extracted using `getppid` fucntion.
```
#include <unistd.h>
pid_t fork(void);
//double return: 0 in child, process ID of child in parent, -1 on error.
```
There are two typical uses of `fork`:
1. The process makes a copy of itself and handles one operation while the child operates on another task.
2. A process wants to execute another program. This is accomplished by first creating a new process by calling `fork` and then calling `exec`. Thus, the child replaces itself with the new program. This paradigm is common in shells.

`exec` functions come in six different flavors, with `execve` being the final function. The reason for different flavors is basically the difference in usage of these function. They return to the caller only if there's an error. Below is the list of the different versions that can be use, but don't forget that all of them eventually call `execve`.
```
//notice how the arguments are terminated with a null pointer.
int execl(const char *pathname, const char *arg0, .... (char *) 0);
int execv(const char *pahtname, char *const argv[]);
int execle(const char *pathname, const char *arg0,...(char *), char *const envp[]);

int execve(const char *pathname, char *const argv[], char *const envp[]);

int execlp(const char *filename, const char *arg0,.... (char *) 0);
int execvp(const char *filename, char *const argv[]);
```
A simple mnemonic can be used to memorize the arguments of above functions: arguments in comma-separated list? l: v. Have environment variable been sent? e: nothing. Sending filenamr? p: nothing.

## Concurrent Servers
When client requests can take longer to service, we do not want to tie up a single server with one client; we want to handle muliple clients at the same time. The simplest idea is to write a **concurrent server** under Unix to `fork` a child process to handle each client. Given below is a simple concept of the same.
```
pid_t pid;
int listenfd, connfd;
create, bind, and listen to a socket.
for (;;){
    connfd = accept(listen, ..); /*probably blocks.*/
    
    if ((pid = Fork()) == 0){
        close(listenfd); //child closes listening socket.
        doSomething(connfd); //process the request.
        close(connfd); //done with this client.
        exit(0); //child terminates.
    }
    close(connfd); //parent closes connected socket.
}
```
We know that `close` on a TCP socket causes FIN to be sent, followed by the normal TCP connection termination sequence. But, then why didn't the `close` of connfd by the parent terminate its connection with the client. To understand this, we must understand that every file or socket has a reference count. The reference count is maintained in the file table entry. This is a count of the number of descriptors that are currently open that refer to this file or socket. When `socket` in the parent is called, the file entry associated with connfd has count 1. But when `fork` return, both descriptors are shared between that parent and the child, so the file entries associated now has reference count 2. When the parent closes `connfd`, it just decrements the count by 1 and everything works as expected. The actual cleanup and de-allocation doesn't take place until the reference count reaches 0. Also, pay attention to other descriptors being closed at differnt place.
### `close` Function
`close` function is used to close a socket and terminate a TCP connection. Well, as we discussed in the previous section, `close` doesn't actually close the connection by send FIN on a TCP connection unless the reference count is 0. When called, it decreases the reference count for a given socket descriptor in the file table entry.
```
#include <unistd.h>
int close(int sockfd);
//returns 0 if OK, -1 on error.
```
**Aside:** If we really want to send a FIN on a TCP connection, the `shutdown` function can be used instead of `close`. Sockets have to be closed by the child and parent both because of two reason: 1. a limited number of descriptors are available to any process. 2. The connection might not close on the client side.
### `getsockname` and `getpeername` Functions
These two functions return either the local protocol address associated with a socket (`getsockname`) or the foreign protocol address associated with a socket (`getpeername`). Look up 4.10 for a beautiful description of a particular usage in the context of inetd running telnet.
```
#include <sys/socket.h>
int getsockname(int sockfd, struct sockaddr *localaddr, socklen_t *addrlen);
int getperrname(int sockfd, struct sockaddr *peeraddr, socklen_t *addrlen);
//Both return:0 if OK, -1 on error.
```
**Practice:** Write a function to get the address family of a socket. Hint: user a pointer type  sockaddr\_storage and call getsockname and extract the ss\_family.
____
# TCP Client/Server Example

