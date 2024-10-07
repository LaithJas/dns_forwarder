package handlers

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// a struct that represent the header of a DNS message
type header struct {
	ID     uint16
	QR     bool // one bit field that specifies weather it's a query(0) or response(1)
	OPCODE uint8

	AA bool // Authoritative answer
	TC bool // TrunCation
	RD bool // Recursion Desired
	RA bool // Recursion Avilable
	// bit 10 must be 0 in all Qs and Rs

	RCODE uint8

	flags   uint16
	QDCOUNT uint16 // number of entires in the quesiton section
	ANCOUNT uint16 // number of resource records in the answer section
	NSCOUNT uint16 // number of name server resource records in the authority records section
	ARCOUNT uint16 // number of resource records in the additional records section
}

type questionSection struct {
	QNAME  string
	QTYPE  uint16
	QClASS uint16
}

type resourceRecord struct {
	name string
	// rData    []byte
	rData    R_data
	ttl      uint32
	rType    uint16
	class    uint16
	rDLength uint16
}

var rr_types = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	257: "CAA",
	35:  "NAPTR",
	43:  "DS",
	48:  "DNSKEY",
	52:  "TLSA",
	255: "ANY",
}

var rr_classes = map[uint16]string{
	1:   "IN",
	2:   "CS",
	3:   "CH",
	4:   "HS",
	255: "ANY",
}

func parseHeader(dnsMsg []byte) (*header, error) {
	if len(dnsMsg) < 12 {
		return nil, fmt.Errorf("DNS Message is too short")
	}

	// creating a new instance of 'header' struct
	msg := new(header)

	msg.ID = binary.BigEndian.Uint16(dnsMsg[0:2])
	msg.flags = binary.BigEndian.Uint16(dnsMsg[2:4])
	// start parsing flags
	flags := msg.flags
	msg.QR = flags&0x8000 != 0
	msg.OPCODE = uint8((flags >> 11) & 0x0F)
	msg.AA = flags&0x0400 != 0
	msg.TC = flags&0x0200 != 0
	msg.RD = flags&0x0100 != 0
	msg.RA = flags&0x0080 != 0
	msg.RCODE = uint8(flags & 0x000F)
	// End parsing flags

	msg.QDCOUNT = binary.BigEndian.Uint16(dnsMsg[4:6])
	msg.ANCOUNT = binary.BigEndian.Uint16(dnsMsg[6:8])
	msg.NSCOUNT = binary.BigEndian.Uint16(dnsMsg[8:10])
	msg.ARCOUNT = binary.BigEndian.Uint16(dnsMsg[10:12])

	return msg, nil
}

// parseQuestionSection parses the question section of the DNS message.
// it returns a struct with the domain name as a string and other values as uint16
// TODO: maybe remove the returned error, or make it useful
func parseQuestionSection(dnsMsg []byte) (*questionSection, int, error) {
	msg := &questionSection{}
	domain_name, n := parseDomainName(dnsMsg, 0)
	msg.QNAME = domain_name
	msg.QTYPE = binary.BigEndian.Uint16(dnsMsg[n : n+2])
	msg.QClASS = binary.BigEndian.Uint16(dnsMsg[n+2 : n+4])

	return msg, n + 4, nil
}

func parseResourceRecord(data []byte, offset int, rr_count int) []*resourceRecord {
	// TODO:  need a slice to store multiple RRs
	rr_list := []*resourceRecord{}
	var n int
	var dn_len int

	for i := 0; i < rr_count; i++ {
		rr := &resourceRecord{}
		dn_offset := get_pointer(data, offset)
		if dn_offset == -1 {
			rr.name, dn_len = parseDomainName(data, offset)
			n = offset + dn_len
		} else {
			rr.name, _ = parseDomainName(data, dn_offset)
			n = offset + 2
		}
		rr.rType = binary.BigEndian.Uint16(data[n : n+2])
		rr.class = binary.BigEndian.Uint16(data[n+2 : n+4])
		rr.ttl = binary.BigEndian.Uint32(data[n+4 : n+8])
		rr.rDLength = binary.BigEndian.Uint16(data[n+8 : n+10])
		rr.rData, _ = parseRData(data, n+10, int(rr.rDLength), rr.rType)
		rr_list = append(rr_list, rr)
		offset = n + 10 + int(rr.rDLength)

	}

	return rr_list
}

// returns the domain name given the DNS request message byte string
// returns the name as a string, and the amount of bytes that were read
func parseDomainName(dnsMsg []byte, offset int) (string, int) {
	var qname string
	var qnameLen int
	// Loop through each label in QNAME
	for {
		length := int(dnsMsg[offset])
		if length == 0 {
			qnameLen++ // Add 1 for the null byte
			break
		}

		offset++               // Move past the length byte
		qnameLen += length + 1 // Add label length + 1 (for the length byte)
		label := dnsMsg[offset : offset+length]
		qname += string(label) + "."
		offset += length
	}

	return qname, qnameLen
}

func get_pointer(data []byte, offset int) int {
	ptr := strconv.FormatUint(uint64(int(data[offset])), 2)
	if ptr[:2] == "11" {
		ptr_val := strconv.FormatUint(uint64(int(data[offset+1])), 2)
		ptr_val = ptr[2:] + ptr_val
		new_offset, _ := strconv.ParseInt(ptr_val, 2, 64)
		return int(new_offset)
	}
	return -1
}
