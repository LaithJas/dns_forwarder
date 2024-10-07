package handlers

import (
	"encoding/binary"
	"fmt"
	"net"
)

type R_data interface {
	Parse(data []byte) (R_data, error)
	String() string
}

// IPV4 RR
type A_record struct {
	IP [4]byte
}

func (a *A_record) Parse(data []byte) (R_data, error) {
	if len(data) != 4 {
		return nil, fmt.Errorf("Invalid data length for record")
	}
	a.IP = [4]byte{data[0], data[1], data[2], data[3]}
	return a, nil
}

func (a *A_record) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", a.IP[0], a.IP[1], a.IP[2], a.IP[3])
}

// CNAME RR
type CNAME_record struct {
	Domain_name string
}

// TODO: there is a problem when parsing this one, Im going to
// remove it from the switch stmt for now
func (r *CNAME_record) Parse(data []byte) (R_data, error) {
	r.Domain_name, _ = parseDomainName(data, 0)
	return r, nil
}

func (r *CNAME_record) String() string {
	return r.Domain_name
}

// IPV6
type IP6_record struct {
	IP net.IP
}

func (a *IP6_record) Parse(data []byte) (R_data, error) {
	if len(data) != 16 {
		return nil, fmt.Errorf("Invalid data length for recrod")
	}

	a.IP = net.IP(data)
	return a, nil
}

func (a *IP6_record) String() string {
	return a.IP.String()
}

type MX_recrod struct {
	preference uint16
	mx_name    string
}

func (mx *MX_recrod) Parse(data []byte) (R_data, error) {
	mx.preference = binary.BigEndian.Uint16(data[:2])
	mx.mx_name, _ = parseDomainName(data[2:], 0)
	return mx, nil
}

func (mx *MX_recrod) String() string {
	return fmt.Sprintf("%d %s", mx.preference, mx.mx_name)
}

type NS_record struct {
	Domain_name string
}

func (ns *NS_record) Parse(data []byte) (R_data, error) {
	ns.Domain_name, _ = parseDomainName(data, 0)
	return ns, nil
}

func (ns *NS_record) String() string {
	return ns.Domain_name
}

func parseRData(data []byte, offset int, rdLength int, rrType uint16) (R_data, error) {
	rdata := data[offset : offset+rdLength]
	var rr R_data

	switch rrType {
	case 1:
		rr = &A_record{}
	case 2:
		rr = &NS_record{}
	case 15:
		rr = &MX_recrod{}
	case 28:
		rr = &IP6_record{}
	default:
		return nil, fmt.Errorf("Record Type is unrecognized or still under development")
	}

	rr.Parse(rdata)
	return rr, nil
}
