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