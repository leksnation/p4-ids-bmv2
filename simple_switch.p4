/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IPPROTO_TCP   = 6;
const bit<16> TCP_PORT_HTTP = 80;

/* ------------------------------------------------------------------ */
/* Headers                                                            */
/* ------------------------------------------------------------------ */
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  reserved;
    bit<8>  flags;          // bit1 = SYN
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct metadata { }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/* ------------------------------------------------------------------ */
/* Parser                                                             */
/* ------------------------------------------------------------------ */
parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_TCP: parse_tcp;
            default:     accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/* ------------------------------------------------------------------ */
/* Checksum verification (empty – we recalc later)                    */
/* ------------------------------------------------------------------ */
control VerifyChecksumImpl(inout headers hdr, inout metadata meta) {
    apply { }
}

/* ------------------------------------------------------------------ */
/* Ingress – IDS + forwarding                                         */
/* ------------------------------------------------------------------ */
control IngressImpl(inout headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {

    /* ---- actions -------------------------------------------------- */
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<48> dst_mac, bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* ---- table ---------------------------------------------------- */
    table bad_sources {
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.tcp.dst_port  : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {

            /* SYN packet to HTTP? */
            bool is_syn = (hdr.tcp.flags & 0x02) == 0x02;
            bool is_http = (hdr.tcp.dst_port == TCP_PORT_HTTP);

            if (is_syn && is_http) {
                /* check blacklist */
                if (!bad_sources.apply().hit) {
                    /* not blacklisted → normal forward */
                    /* toggle port for 2-port test topology */
                    bit<9> out_port = (bit<9>)standard_metadata.ingress_port ^ 9w1;
                    forward(48w0x001122334455, out_port);
                }
                /* else: drop() already called by table */
            } else {
                /* non-SYN or non-HTTP → forward */
                bit<9> out_port = (bit<9>)standard_metadata.ingress_port ^ 9w1;
                forward(48w0x001122334455, out_port);
            }
        } else {
            drop();
        }

        /* recompute IPv4 checksum after TTL decrement */
        hdr.ipv4.hdr_checksum = hdr.ipv4.hdr_checksum + 16w0x0100;
    }
}

/* ------------------------------------------------------------------ */
/* Egress (nothing)                                                   */
/* ------------------------------------------------------------------ */
control EgressImpl(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {
    apply { }
}

/* ------------------------------------------------------------------ */
/* Checksum computation                                               */
/* ------------------------------------------------------------------ */
control ComputeChecksumImpl(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.total_len, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.frag_offset,
              hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.src_addr, hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

/* ------------------------------------------------------------------ */
/* Deparser                                                           */
/* ------------------------------------------------------------------ */
control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/* ------------------------------------------------------------------ */
/* Switch                                                             */
/* ------------------------------------------------------------------ */
V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;