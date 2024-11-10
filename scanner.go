package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"syscall"
)

// The function for data consistency
func checkSum(data []byte) uint16 {
	sum := uint32(0)
	/*
	EXAMPLE:
		data[i]=0xFF 
		and 
		data[i+1]=0x65
		sum = sum + 0xFF65
	*/
	for i := 0; i < len(data) - 1; i += 2 {
		sum += uint32(data[i]) << 8 + uint32(data[i + 1])
	}

	/*
	EXAMPLE:
		data[len(data) - 1]=0x88
		sum = sum + 0x8800

		data[i] = 0000 0000 0000 0000 0000 0000 0000 0001 -> 0x01
		0000 0000 0000 0000 0000 0001 0000 0000
		data[i + 1] = 0000 0000 0000 0000 0000 0000 0000 0001 -> 0x01
		0000 0000 0000 0000 0000 0001 0000 0001

		RESULT: 0x0101
	*/
	if len(data) % 2 == 1 {
		sum += uint32(data[len(data) - 1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	return uint16(^sum)
}


func tcpCheckSum(srcIP net.IP, dstIP net.IP, tcpSegment []byte) uint16 {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP)
	copy(pseudoHeader[4:8], dstIP)
	pseudoHeader[8] = 0
	pseudoHeader[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpSegment)))

	sumData := append(pseudoHeader, tcpSegment...)
	return checkSum(sumData)
}

func createSynPacket(srcIP string, dstIP string, srcPort uint16, dstPort uint16) []byte {

	readyToUseSrcIP := net.ParseIP(srcIP).To4()
	readyToUseDstIP := net.ParseIP(dstIP).To4()


	// Creating buffer for packet (IP-header 20 bytes + TCP-header 20 bytes)
	packet := make([]byte, 40)

	// IP-Header
	packet[0] = 0x45  // Version=4 and length=5 * 4 = 20 bytes, it takes 8 bit (0x45 - 1 byte)
	packet[1] = 0x00  // TOS
	binary.BigEndian.PutUint16(packet[2:4], 40) // Length of packet (IP + TCP)
	binary.BigEndian.PutUint16(packet[4:6], 54321) // Identification
	packet[6] = 0x40 // FLAGS
	packet[7] = 0x00 // Fragment Offset
	packet[8] = 64   // TTL
	packet[9] = syscall.IPPROTO_TCP
	copy(packet[12:16], readyToUseSrcIP) // Source address
	copy(packet[16:20], readyToUseDstIP) // Destination address

	// IP-Header checksum
	binary.BigEndian.PutUint16(packet[10:12], checkSum(packet[:20]))

	// TCP-Header
	binary.BigEndian.PutUint16(packet[20:22], srcPort) // Source Port
	binary.BigEndian.PutUint16(packet[22:24], dstPort) // Destination Port
	binary.BigEndian.PutUint32(packet[24:28], 0) // Sequence number
	binary.BigEndian.PutUint32(packet[28:32], 0) // Confirmation number
	packet[32] = 0x50 // Length of TCP-header (5 words = 5 * 4 = 20 bytes)
	packet[33] = 0x02 // FLAGS (SYN = 0x02)
	binary.BigEndian.PutUint16(packet[34:36], 64240) // Window
	packet[36] = 0x00
	packet[37] = 0x00
	packet[38] = 0x00
	packet[39] = 0x00

	// Checksum of TCP-header
	cs := tcpCheckSum(readyToUseSrcIP, readyToUseDstIP, packet[20:])
	binary.BigEndian.PutUint16(packet[36:38], cs)

	return packet
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