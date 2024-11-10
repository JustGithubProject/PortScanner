package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"syscall"
)

func createSynPacket(srcIP string, dstIP string, srcPort uint16, dstPort uint16) {

	readyToUseSrcIP := net.ParseIP(srcIP).To4()
	readyToUseDstIP := net.ParseIP(dstIP).To4()


	// Creating buffer for packet (IP-header 20 bytes + TCP-header 20 bytes)
	packet := make([]byte, 40)
	packet[0] = 0x45  // Version=4 and length=5 * 4 = 20 bytes, it takes 8 bit (0x45 - 1 byte)
	packet[1] = 0x00  // TOS
	binary.BigEndian.PutUint16(packet[2:4], 40) // Length of packet (IP + TCP)
	binary.BigEndian.PutUint16(packet[4:6], 54321) // Identification
	packet[6] = 0x40 // FLAGS
	packet[7] = 0x00 // Fragment Offset
	packet[8] = 64   // TTL
	packet[9] = syscall.IPPROTO_TCP
	copy(packet[12:16], readyToUseSrcIP)
	copy(packet[16:20], readyToUseDstIP)

	// TODO ...


}




func main() {
	// Destination host and port
	host := "scanme.nmap.org"
	port := 80

	// Converting host to IP
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Println("Failed to convert domain to IP")
		os.Exit(1)
	}

	ip := ips[0].To4()
	if ip == nil {
		log.Println("Invalid ip-address")
		os.Exit(1)
	}

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

	// Prepare the destination address struct
	sa := &syscall.SockaddrInet4{
		Port: port,
	}

	copy(sa.Addr[:], ip)

	// TODO: I need to create syn packet
}