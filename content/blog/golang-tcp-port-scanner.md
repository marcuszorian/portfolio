---
title: "Golang TCP Port Scanner"
date: 2026-01-04T18:30:40+11:00
draft: false
---

[Github Project](https://github.com/marcuszorian/TCP-Port-Scanner)

## Background

### What is a TCP Port Scanner

A TCP port scanner checks which TCP ports on a target system are open or closed by sending packets to each port and analysing the responses. If the port is open, the target responds with a SYN-ACK packet. If it's closed, the target responds with an RST packet. No response or a timeout typically indicates the port is filtered (blocked by a firewall or unreachable).

This program performs a full connection scan (also known as a connect scan), which completes the TCP handshake. It differs from a SYN scan (or half-open scan), which only sends a SYN packet and never completes the handshake. The program initiates the handshake with a SYN, receives a SYN-ACK for open ports, and sends an ACK to complete the connection. If no response is received, the port is considered filtered.

While less stealthy than a SYN scan, this method is easier to implement and doesn't require low-level packet manipulation.

The diagram below illustrates the TCP connection process for a full connection scan.

![TCP Connect Scan](/tcp-port-scanner/tcp-connect-scan.png)

*Image courtesy of [Nmap's Connect Scan Methodology](https://nmap.org/book/scan-methods-connect-scan.html)*

### Dangers of having open ports

Open TCP ports increase security risk by exposing network services that attackers can target. These exposed services may be vulnerable to exploits, brute-force credential attacks, or traffic interception, especially when unencrypted protocols like FTP (ports 20/21), Telnet (port 23), or HTTP (ports 80/8080) are used. Closing or filtering unused ports helps reduce the attack surface and prevent unauthorised access.

## Program

### Overview

The program scans a specified host for open TCP ports using multiple goroutines and channels. It reports open ports along with common service names and supports scanning either well-known ports (1–1024) or the full range (1–65535).

### Usage

```bash
go run main.go <hostname> [full]
# or
go build -o portscan main.go
./portscan <hostname> [full]
```

- Default: scans ports 1–1024  
- With `full`: scans ports 1–65535

### Example Output

```
$ ./portscan scanme.nmap.org
22: SSH/SCP (open)
80: HTTP (open)
```

## Full Code

```go (filename="portscanner.go")
package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// common ports sourced from https://www.uninets.com/blog/what-is-tcp-port

var common_ports = map[int]string{
	20:   "FTP Data",
	21:   "FTP Control",
	22:   "SSH/SCP",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	8080: "HTTP Alt",
	8443: "HTTPS Alt",
}

type PortRange struct {
	Start, End int
}

func getOpenPorts(hostname string, ports PortRange) {
	portChan := make(chan int, 100)
	resultChan := make(chan int, 100)
	var waitGroup sync.WaitGroup

	// Create 100 workers
	for i := 0; i < 100; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for port := range portChan {
				if scanPort(hostname, port) {
					resultChan <- port
				}
			}
		}()
	}

	// Feed ports to queue
	go func() {
		defer close(portChan)
		for i := ports.Start; i <= ports.End; i++ {
			portChan <- i
		}
	}()

	// Close results after workers done
	go func() {
		waitGroup.Wait()
		close(resultChan)
	}()

	// Collect + print open ports
	var openPorts []int
	for port := range resultChan {
		openPorts = append(openPorts, port)
	}
	sort.Ints(openPorts)

	for _, port := range openPorts {
		if service, ok := common_ports[port]; ok { // if service exists in commmon_ports
			fmt.Printf("%d: %s (open)\n", port, service)
		} else {
			fmt.Printf("%d: unknown (open)\n", port)
		}
	}
}

func scanPort(hostname string, port int) bool { // Perform connect scan on port
	address := hostname + ":" + strconv.Itoa(port) // hostname:port
	conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond) // Attempts TCP connection to address, returning conn if successful or err otherwise
	if err != nil {
		return false
	}
	defer conn.Close() // close once the timeout has been finished | defer is used to delay execution until the above DialTimeout is finished
	return true
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: ./portscan <hostname> [full scan]")
		os.Exit(1)
	}
	hostname := os.Args[1]

	// Validate hostname
	if _, err := net.LookupIP(hostname); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid hostname %s: %v\n", hostname, err)
		os.Exit(1)
	}

	// Check for full flag (args[2])
	isFull := len(os.Args) > 2 && (os.Args[2] == "full" || os.Args[2] == "true")
	if isFull {
		getOpenPorts(hostname, PortRange{Start: 1, End: 65535})
	} else {
		getOpenPorts(hostname, PortRange{Start: 1, End: 1024})
	}
```

## Optimisation

### Old getOpenPorts function:

```go (filename="portscanner.go")
func getOpenPorts(hostname string, ports PortRange) {
    for i := ports.Start; i <= ports.End; i++ {
        open := scanPort(hostname, i)
        if open {
            if service, ok := common_ports[i]; ok {
                fmt.Printf("%d: %s (open)\n", i, service)
            } else {
                fmt.Printf("%d: unknown (open)\n", i)
            }
        }
    }
}
```

Originally, the program was created with a single-threaded design, meaning that it was impossible to test multiple ports simultaenously.

```go (filename="portscanner.go")
conn, err := net.DialTimeout("tcp", address, 5*time.Second)
```

Additionally, I applied a 5-second TCP timeout, which further amplified the problem. In combination with the single-threaded design, scanning 1024 ports could take 85+ minutes in the worst case.

### Resolution

The optimized version uses Go's concurrency primitives:

1. 100 concurrent worker goroutines test ports simultaneously
2. Channels (portChan, resultChan) coordinate workload distribution and results
3. 250ms timeout (20x faster failure detection)
4. sync.WaitGroup ensures all workers complete before printing

```go (filename="portscanner.go")
	portChan := make(chan int, 100)
	resultChan := make(chan int, 100)
```

## Acknowledgements

Credits to Kelvin Mai for the tutorial
- https://www.youtube.com/watch?v=KW8jls13YOY
- https://github.com/kelvin-mai/go-port-scanner

Common ports sourced from https://www.uninets.com/blog/what-is-tcp-port
