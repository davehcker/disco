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
**Practice:** Write a function to get the address family of a socket. Hint: user a pointer type  sockaddr\_storage and call `getsockname` and extract the ss\_family.
____
# TCP Client/Server Tips
## POSIX Signal Handling
A ***signal*** is a notification to a process that an event has occurred. Signals are sometimes called ***software interrupts***. Signals usually occur ***asynchronously*** i.e. a process doesn't know ahead of time when a signal will occur. Signal can be sent:
* By one process to another (or to itself)
* By the kernel to a process

The SIGCHLD signal is sent by the kernel whenever a process terminates, to the parent of the terminating process. Every signal can be handled by calling `sigaction` function. To handle a signal, we have three choices that define the *disposition* of the signal:
1. We can define *signal handler* to *catch* a signal. The two signals SIGKILL, and SIGSTOP cannot be caught. The function prototype of a signal handler is: `void handler(int signo)`. It just needs the signal number.
2. We can *ignore* a signal by setting its disposition to SIG_IGN. The two signals SIGKILL and SIGSTOP can't be ignored.
3. We can set the *default* disposition for a signal by setting its disposition to SIG_DFL. The default is normally to terminate a process on receipt of a signal. Signals like SIGCHLD and SIGURG have default disposition to be ignored.

## `signal` Function
Inorder to set signal handlers, we can use `signal`. But it is better to use POSIX `sigaction`. Becuase `sigaction` is so complicated, it is better to write a wrapper function for setting signal handlers. Below is an example:
```
#include <signal.h>
typedef void Sigfunc(int);
Sigfunc * signal(int signo, Sigfunc *func){
	struct sigaction act, oact;
    
    act.sa_handler = func;
    sigemptyset(&act.sa_mask); //dont block other signals
    act.sa_flags = 0;
    if (signo == SIGALRM)
    	act.sa_flags |= SA_INTERRUPT (or SA_RESTART);
    
    if (sigaction(signo, &act, &oact) < 0)
    	return (SIG_ERR);
    return (oact.sa_handler);
    
    //sigaction: returns 0 on success; on error, -1 is returned, and errno
     is set to indicate the error.
	//if oact is NON-NULL, the previos action is stored to it.
    //SA_RESTART, if set, a system flag call interrupted by this signal will be 
    automatically restarted by the kernel.
}
```
Some important points about signals:
* Once a signal is installed, it remains installed.
* While a signal handler is executing, the signal being delivered is blocked. Furthermore, other additional signals that were specified in the *sa_mask* will also be blocked.
* By default Unix signals are not queued. If a signal is blocked, all the remaining same signals will be ignored.
* `sigprocmask` can be used to selectively block and unblock a set of signals.

## Handling `SIGCHLD` Signals
If a process terminates, and that process has childten in the zombie state, the parent process ID of all the zombie children is set to 1 (the `init` process), which will inherit the children and clean them up i.t. `init` will `wait` for them, which removes the zombie. In order to avoid zombies being created, we can install a signal handler to catch SIGCHLD, which calles `wait` inside it.      
Here's a simple error handler:
```
void sig_chld(int signo){
  pid_t pid;
  int stat;

  pid = wait(&stat);
  printf("child &d terminated\n", pid);//calling standard I/O is not recommended.
  return;
}
```
**Interrupted System Calls** Most networking functions (`accept` for example) are "slow system calls" i.e. the call need never return. Read and write calls are also slow system calls. When such a funcion call is blocked in a slow system call, and the process catches a signal and the handler returns, the system call returns EINTR. Some kernels automatically restart the call, some don't. For protability, therefore, when writing a program that catches signals, we must be prepared for slow system calls to return EINTR. With functions like `accept` and `read`, we can just restart by calling the function repeatedly in a loop and checking if an EINTR was caught. But we can't do the same with `connect`. In other words, the problem with a function like `connect` is that it can't be restarted immediately. In such cases, we must use `select`.

## `wait` and `waitpid` Functions
```
#include <sys/wait.h>
pid_t wait(int *statloc);
pit_t waitpid(pid_t pid, int *statloc, int options);
//both return process ID if OK, 0 or -1 on error.
```
In one of the previous discussions, we used `wait` to handle the terminated child. If there are no terminated children for the process calling `wait`, but the process has one or more children executing, then `wait` blocks until the first of the waiting childrn terminates.        
`waitpid` gives us more control over which process to wait for and whether or not to block. A value of -1 for *pid* tells us to wait for the first of the children. Similarly, among various *options*, WNOGHANG tells the kernel not to block if there are no terminated children. Consider an example where we fork the server into 10 processes, and all the clients close the connection immediately, in this case, we are most likely to miss many signals as they won't be queued when the handler is already handling one. Below is a possible solution using `waitpid` to write the signal handler. Why can't we use `wait` instead?
```
void sig_child(int signo){
	pid_t pid;
    int stat;
    while((pid = waitpid(-1 &stat, WNOHANG)) > 0)
    	printf("Child %d terminated\n", pid);
 		return;
}
```
Main points:
* We must catch the SIGCHLD signal when `fork`ing child processes.
* We must handle interrupted system calls when catching signals.
* A SIGCHLD handler must be coded correctly using `waitpid` to prevent any zombies to be left around.

## Server Process Termination
Imagine an echo server/client programs where the client writes a line to the server and the server returns the same line. We start the server as usual, the client connects. After successful three-way handshake, the client is waiting on the system call to I/O from the user. While the client is still blocked in the I/O call, the server terminates its process. This causes the client to receive a FIN, but because the client was still blocked in the I/O call, as soon as it gets the line from the user, it writes to the server. The server had already sent a FIN, so it simply resets the connection by sending RST. Interestingly, the client didn't see RST either, because immediately after writing to the socket, it went to the I/O call again. But when the client goes back to read, `read` unexpectedly reads EOF (because of the FIN that it received earlier). The client might then print (upon reading EOF) "server terminated prematurely".
### `SIGPIPE` Signal
In the above scenario, after the first write, the client received an RST. What happens when the client tries to write again i.e. after the first write returns an RST? In this case, when the process tries to write to a socket that has already received an RST, the SIGPIPE signal is sent to the process. The default action of this signal is to terminate the process.       
If the process either catches the signal and returns from the signal handler, or ignores the signal, the write operation returns EPIPE.        
The recommended way to handle SIGPIPE depends on the application specifics. For instance, on might want to commit it to a log file (after receiving SIGPIPE)   
**NOTE:**.If multiple sockets are in use, the delivery of the signal will not tell us which socket encountered the error. If we need to know which write caused the erro, then we must either ignore the signal or return from the signal handler and handle EPIPE from the `write`.
### Crashing of Server Host
1. When the server host crashes, nothing is sent out on the existing network connections. 
2. After writing the line, the client process keeps waiting for an echoed reply.
3. Different systems wait and resend the data for different number of times. If there were no responses, the error is ESTIMEDOUT. But if some intermediate router detects that the server was unreachable with an ICMP "server unreachable" messagem the message is either EHOSTUNREACH or ENENTUNREACH.        

**Aside:** In onrder to avoid waiting for reply for a time set by the server, we can place a timeout on call to `readline`. We can also use the SO_KEEPALIVE option to detect server crashing even when we're not actively sending it data.
### Crashing and Rebooting of Server Host
1. Connection is established.
2. The server crashes and reboots.
3. We send a line of input, but when the server reboots, its TCP loses all information. The server simply responds back with an RST.
4. The client is blocked in I/O call when it the RST is received, causing the readline to return the error ECONNRESET.       

Possible solutions may be setting SO_KEEPALIVE, or some client/server hearbeat function.
### Shutdown of Server Host
When a Unix system is shut down, the `init` process normally send the SIGTERM signal to all processes( we can cathc this signal), waits some fixed amount of time, and then sends the SIGKILL signal (which we can't catch). This gives all running processes a short amount of time to clean up and terminate. If we do not catch SIGTERM and terminate, our server will be terminated by the SIGKILL signal. When the process terminates, all open descriptors are closed. We must, therefor, use the `select` or `poll` function in our client to have the client detect the termination of the server process.
