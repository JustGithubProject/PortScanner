# PortScanner - Half-Open Scanning (SYN Scan)

This is a simple Go-based port scanner that performs a **half-open scanning** (also known as **SYN scanning**). It is designed to check if a specific port on a target machine is open or closed. This technique sends a SYN packet to the target and waits for a response, without completing the TCP handshake, making it less detectable by firewalls or intrusion detection systems.

### You need to specify your TARGET HOST AND PORT
host := "scanme.nmap.org"
port := 80


```go build scanner.go```
```sudo ./scanner```