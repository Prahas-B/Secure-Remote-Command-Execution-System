# Secure Remote Command Execution System

## Overview

The Secure Remote Command Execution System is a client-server based application that allows authenticated users to remotely execute system commands on a server in a secure manner.

The system ensures:

* Secure communication using SSL/TLS
* User authentication
* Command execution on server
* Audit logging of activities
* Support for multiple clients

---

## Objectives

* Implement low-level socket programming using TCP
* Ensure secure communication using SSL/TLS
* Design a structured communication protocol
* Enable remote command execution
* Maintain logs for auditing and analysis

---

## System Architecture

```
        Client 1                Client 2
        --------                --------
            |                      |
            |      TCP + SSL      |
            |----------------------|
                      |
                      |
                   Server
            (Command Execution)
```

---

## Features

### Authentication

* Users must log in using:

  ```
  LOGIN <username> <password>
  ```
* Credentials are verified using `users.txt`

---

### Secure Communication

* Uses SSL/TLS (OpenSSL) for encrypted communication
* Prevents data interception and tampering

---

### Remote Command Execution

* Clients send commands in structured format:

  ```
  CMD <command>
  ```
* Server executes commands and returns output

---

### Audit Logging

* All commands are logged in:

  ```
  audit.log
  ```
* Example:

  ```
  [10:01] alice executed ls
  [10:02] bob executed pwd
  ```

---

### Multiple Clients

* Server supports multiple concurrent clients
* Implemented using fork() / threads

---

### Performance Analysis

* Client measures response time for each command
* Used to analyze overhead due to SSL

---

## Project Structure

```
project/
│
├── client.c        # Client-side implementation
├── server.c        # Server-side implementation
├── users.txt       # User credentials
├── audit.log       # Command logs
├── server.crt      # SSL certificate
├── server.key      # SSL private key
└── README.md
```

---

## Technologies Used

* C Programming Language
* TCP Socket Programming
* OpenSSL (SSL/TLS)
* Linux/Ubuntu Environment

---

## Setup Instructions

### 1. Install Dependencies

```
sudo apt update
sudo apt install libssl-dev
```

---

### 2. Compile Programs

Client:

```
gcc client.c -o client -lssl -lcrypto
```

Server:

```
gcc server.c -o server -lssl -lcrypto
```

---

### 3. Generate SSL Certificates (Server Side)

```
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
```

---

### 4. Run the Server

```
./server
```

---

### 5. Run the Client

```
./client <SERVER_IP>
```

Example:

```
./client 192.168.1.23
```

---

## Example Usage

```
LOGIN alice 1234
CMD ls
CMD pwd
EXIT
```

---

## Sample Output

```
Connected to secure server
SSL/TLS handshake completed

LOGIN alice 1234
Authentication Successful

CMD ls
server.c
client.c

Response Time: 0.0023 seconds
```

---

## Learning Outcomes

* Understanding of TCP client-server architecture
* Hands-on experience with SSL/TLS
* Knowledge of secure system design
* Practical exposure to process handling and logging

---

## Team Contributions

| Member   | Responsibility     |
| -------- | ------------------ |
| Member 1 | Server development |
| Member 2 | Client development |
| Member 3 | Security & logging |

---

## Notes

* Ensure all devices are on the same network
* Server must be running before client connects
* Port number must match on both sides

---

## Conclusion

This project demonstrates a secure and efficient method for remote command execution using low-level networking and cryptographic techniques.
