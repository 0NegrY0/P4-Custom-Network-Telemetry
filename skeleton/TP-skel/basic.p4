/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_INT = 253; // Número de protocolo customizado para o nosso Shim Header
const bit<8> MAX_HOPS = 255;      // Agora podemos usar quantos saltos quisermos!

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// MASTER - Cabeçalho interno logo após o IP (4 bytes)
header int_master_t {
    bit<8>  next_proto; // Guarda o protocolo original (1=ICMP, 6=TCP, 17=UDP)
    bit<8>  num_slave;
    bit<16> int_length; // Tamanho de toda a telemetria (Master + Slaves)
}

// SLAVE - O salto propriamente dito (8 bytes)
header int_slave_t {
    bit<16> switch_id;
    bit<8>  ingress_port;
    bit<8>  egress_port;
    bit<32> timestamp;
    bit<32> packet_length; 
}

struct metadata {
    bit<8> slave_count;    // Contador interno para o router saber quantos slaves já inseriu
}

struct headers {
    ethernet_t            ethernet;
    ipv4_t                ipv4;
    int_master_t          int_master;
    int_slave_t[MAX_HOPS] int_slave;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        // Desvia para o parser de telemetria se o protocolo for 253
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_INT: parse_int_master;
            default: accept;
        }
    }
    state parse_int_master {
        packet.extract(hdr.int_master);
        meta.slave_count = 0;
        transition select(hdr.int_master.num_slave) {
            0: accept;
            default: parse_int_slaves_loop;
        }
    }
    state parse_int_slaves_loop {
        packet.extract(hdr.int_slave.next);
        meta.slave_count = meta.slave_count + 1;
        transition select(meta.slave_count == hdr.int_master.num_slave) {
            true: accept;
            false: parse_int_slaves_loop;
        }
    } 
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
                 
    apply {
        // Verifica se o IPv4 é válido e se o pacote não vai ser descartado
        // Só aplica INT se o protocolo for estritamente TCP (6) ou UDP (17)
        if (hdr.ipv4.isValid() && standard_metadata.egress_spec != 511 && 
            (hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17 || hdr.ipv4.protocol == IP_PROTO_INT)) {
            
            // --- TRÁFEGO DE APLICAÇÃO ALVO (TCP/UDP) ---
            // O switch insere a telemetria normalmente aqui
            
            if (!hdr.int_master.isValid()) {
                hdr.int_master.setValid();
                hdr.int_master.next_proto = hdr.ipv4.protocol; // Salva o original (6 ou 17)
                hdr.int_master.num_slave = 0;
                hdr.int_master.int_length = 4;
                
                hdr.ipv4.protocol = IP_PROTO_INT; // Altera para o protocolo customizado 253
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
            }

            bit<8> current_hop = hdr.int_master.num_slave;
            
            if (current_hop < MAX_HOPS) {
                hdr.int_slave[current_hop].setValid();
                hdr.int_slave[current_hop].switch_id = (bit<16>) ((hdr.ethernet.srcAddr >> 8) & 0xFF); //derivando switch_id do MAC de origem 
                hdr.int_slave[current_hop].ingress_port = (bit<8>)standard_metadata.ingress_port;
                hdr.int_slave[current_hop].egress_port = (bit<8>)standard_metadata.egress_port;
                hdr.int_slave[current_hop].timestamp = (bit<32>)standard_metadata.ingress_global_timestamp;
                hdr.int_slave[current_hop].packet_length = (bit<32>)standard_metadata.packet_length; 
                
                hdr.int_master.num_slave = (current_hop + 1);
                hdr.int_master.int_length = hdr.int_master.int_length + 12;
                
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 12;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.int_master);
        packet.emit(hdr.int_slave);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
