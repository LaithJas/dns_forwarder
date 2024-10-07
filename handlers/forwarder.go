package handlers

import (
	"fmt"
	"net"
)

// handle_request() is used by run a request agent that will forward the message t
// DNS name server, process the response and resend it to the user who requested it.
func Handle_request(conn *net.UDPConn, client_addr *net.UDPAddr, dns_msg []byte) {
	// forwarding the DNS request to a DNS name server
	response, err := forward_DNS_Request(dns_msg, "8.8.8.8:53")
	if err != nil {
		fmt.Errorf("Failed to forward DNS request:  %v", err)
		return
	}

	// parsing the response to save in cache
	header_len := 12
	response_header, _ := parseHeader(response)
	q_section, offset, _ := parseQuestionSection(response[header_len:])

	total_rr := response_header.ANCOUNT + response_header.NSCOUNT + response_header.ARCOUNT - 1
	print_response(response_header, q_section)
	rr_section := parseResourceRecord(response, offset+header_len, int(total_rr))

	// printing for debugging and visusal presentation
	print_RR(rr_section)
	// fmt.Printf("Name:%s ,TTL:%d, TYPE:%s, Class:%s, RDLength:%d\n ",
	//	rr_section.name, rr_section.ttl, rr_types[rr_section.rType], rr_classes[rr_section.class], rr_section.rDLength) // for Debugging only

	// sending response back to user
	_, err = conn.WriteToUDP(response, client_addr)
	if err != nil {
		fmt.Errorf("Writing to clinet failed!!")
	}
}

// forward_DNS_Request forwards the received DNS request to a given address server address
// it returns the response from the server.
func forward_DNS_Request(request []byte, server_addr string) ([]byte, error) {
	addr, err := net.ResolveUDPAddr("udp", server_addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	// TODO: I can set a TTL using conn.SetDeadline(time.Now().Add(5*time.Second))

	// Send the DNS request
	_, err = conn.Write(request)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 512)

	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

// Print Response requests the response from the query as a strings
// h == header, qs == questionSection
func print_response(h *header, qs *questionSection) {
	fmt.Printf("Header- ID:%d flags:%d questions:%d answers:%d authorities:%d additionals:%d\n",
		h.ID, h.flags, h.QDCOUNT, h.ANCOUNT, h.NSCOUNT, h.ARCOUNT)
	fmt.Printf("Question- name:%s type:%s class:%s\n", qs.QNAME, rr_types[qs.QTYPE], rr_classes[qs.QClASS])
}

func print_RR(rr []*resourceRecord) {
	for _, item := range rr {
		fmt.Printf("Name:%s ,TTL:%d, TYPE:%s, Class:%s, RDLength:%d\n ",
			item.name, item.ttl, rr_types[item.rType], rr_classes[item.class], item.rDLength) // for Debugging only
	}
}
