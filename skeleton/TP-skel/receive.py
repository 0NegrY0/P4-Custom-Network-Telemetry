#!/usr/bin/env python3
import os
import sys
import struct
from scapy.all import sniff, send, hexdump, IP, ICMP

IP_PROTO_INT = 253

def handle_pkt(pkt):
    # Captura apenas pacotes que possuem o Shim Header de INT
    if IP in pkt and pkt[IP].proto == IP_PROTO_INT:
        print("\n" + "="*60)
        print("### [ PACOTE COM TELEMETRIA (SHIM HEADER) ] ###")
        print(f"Origem: {pkt[IP].src} -> Destino: {pkt[IP].dst}")
        
        raw_data = bytes(pkt[IP].payload)
        if len(raw_data) < 4:
            return

        # 1. Extração do Master Header (4 bytes no total)
        # Formato '!BBH' = Unsigned Char(1b), Unsigned Char(1b), Unsigned Short(2b)
        next_proto, num_slave, int_length = struct.unpack("!BBH", raw_data[:4])
        print(f"-> Protocolo Oculto (Original): {next_proto} | Saltos Registrados: {num_slave}")
        print("-" * 60)
        
        # 2. Extração Iterativa dos Slaves (8 bytes cada)
        offset = 4
        for i in range(num_slave):
            if offset + 8 > len(raw_data):
                break
            # Formato '!HBBI' = Short(2b), Char(1b), Char(1b), Int(4b)
            sw_id, in_port, eg_port, ts = struct.unpack("!HBBI", raw_data[offset:offset+8])
            print(f"  [Salto {i+1}] Switch ID: {sw_id} | In: {in_port} | Out: {eg_port} | TS(us): {ts}")
            offset += 8
            
        # 3. Separando o Payload original
        original_payload = raw_data[int_length:]
        
        print("-" * 60)
        # 4. A mágica para o terminal não travar: responder o ping artificialmente!
        if next_proto == 1 and len(original_payload) > 0:
            icmp_layer = ICMP(original_payload)
            if icmp_layer.type == 8: # 8 é o Echo Request do Ping
                print("-> PING (ICMP) detectado no payload original!")
                print("-> receive.py: Forjando e enviando a resposta (Echo Reply) silenciosamente...")
                # Cria a resposta do ping e a envia de volta
                reply = IP(src=pkt[IP].dst, dst=pkt[IP].src) / ICMP(type=0, id=icmp_layer.id, seq=icmp_layer.seq) / icmp_layer.payload
                send(reply, verbose=False)
                
        elif next_proto == 6:
            print("-> Payload TCP puro detectado no fim do cabeçalho.")
        elif next_proto == 17:
            print("-> Payload UDP puro detectado no fim do cabeçalho.")
        
        print("="*60 + "\n")

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    if not ifaces:
        sys.exit(1)
    iface = ifaces[0]
    print(f"Sniffing na interface {iface} aguardando cabeçalhos INT...")
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
