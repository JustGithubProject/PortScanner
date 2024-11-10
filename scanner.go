package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
)

func main() {
	// Destination host and port
	host := "scanme.nmap.org"
	port := 80

	// Create a raw socket (fd -> file descriptor)
	fd, err := syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_RAW,
		syscall.IPPROTO_TCP,
	)

	if err != nil {
		log.Println("Failed to create raw socket")
		os.Exit(1)
	}

	defer syscall.Close(fd)

	// Set socket options
	err = syscall.SetsockoptInt(
		fd,
		syscall.IPPROTO_IP,
		syscall.IP_HDRINCL,
		1,
	)
}