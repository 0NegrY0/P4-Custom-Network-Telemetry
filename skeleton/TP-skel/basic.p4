* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_INT = 0xFD; // Protocolo customizado para indicar pacote INT

// O compilador exige um teto de alocação de memória na pilha, 
// mas o parser será dinâmico usando o numSlave.
const bit<32> MAX_HOPS = 255;

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

header int_master_t {
    bit<32>   sizeSlave;
    bit<32>   numSlave;
}

struct switch_metadata_t {
    bit<32>     id;
}

struct ingress_metadata_t {
    bit<32>     port;
    bit<48>     timestamp;
}

struct egress_metadata_t {
    bit<32>     port;
    bit<48>     timestamp;
}

// 4 bytes (id) + 10 bytes (ingress) + 10 bytes (egress) = 24 bytes (192 bits)
header int_slave_t {
    switch_metadata_t     switchMeta;
    ingress_metadata_t    ingressMeta;
    egress_metadata_t     egressMeta;
}

struct headers {
    ethernet_t            ethernet;
    ipv4_t                ipv4;
    int_master_t          int_master;
    int_slave_t[MAX_HOPS] int_slave; // Pilha de tamanho máximo alocado, mas percorrida dinamicamente
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
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_INT: parse_int_master;
            default: accept;
        }
    }

    state parse_int_master {
        packet.extract(hdr.int_master);
        // Se houver filhos registrados, vai para o estado de extração dinâmica
        transition select(hdr.int_master.numSlave) {
            0: accept;
            default: parse_int_slaves;
        }
    }

    state parse_int_slave {
        // Primitiva de Parser do P4_16 que extrai um número variável de cabeçalhos de uma vez
        // baseada no valor armazenado em hdr.int_master.numSlave
        packet.extract(hdr.int_slave, hdr.int_master.numSlave);
        transition accept;
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
    
    action add_int_hop(bit<32> switch_id) {
        
        // Requisito 1: Inicializa o Master Header se for o primeiro salto
        if (!hdr.int_master.isValid()) {
            hdr.int_master.setValid();
            hdr.int_master.numSlave = 0;
            hdr.int_master.sizeSlave = 24; // O cabeçalho int_slave_t possui 24 bytes (192 bits)
            hdr.ipv4.protocol = IP_PROTO_INT;
            
            // Adiciona o tamanho do Master Header (8 bytes) ao total do IPv4
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8; 
        }

        bit<32> current_hop = hdr.int_master.numSlave;
        
        // Requisito 2 e 3: Inserção e preenchimento do cabeçalho filho no Egress
        if (current_hop < MAX_HOPS) {
            hdr.int_slave[current_hop].setValid();
            
            hdr.int_slave[current_hop].switchMeta.id = switch_id;
            hdr.int_slave[current_hop].ingressMeta.port = (bit<32>)standard_metadata.ingress_port;
            hdr.int_slave[current_hop].ingressMeta.timestamp = (bit<48>)standard_metadata.ingress_global_timestamp;
            hdr.int_slave[current_hop].egressMeta.port = (bit<32>)standard_metadata.egress_port;
            
            // O V1Model expõe o timestamp do Egress (já que estamos no bloco de Egress)
            hdr.int_slave[current_hop].egressMeta.timestamp = (bit<48>)standard_metadata.egress_global_timestamp;
            
            // Atualiza os contadores
            hdr.int_master.numSlave = current_hop + 1;
            
            // Adiciona o tamanho do Slave Header dinamicamente ao comprimento total do IP
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)hdr.int_master.sizeSlave;
        }
    }

    table configure_int {
        actions = {
            add_int_hop;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        // Aplica o mecanismo INT a qualquer pacote IPv4 não dropado
        if (hdr.ipv4.isValid() && standard_metadata.egress_spec != 511) {
            configure_int.apply();
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
