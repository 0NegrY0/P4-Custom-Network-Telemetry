#!/usr/bin/env python3
import os
import sys
import struct
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_addr

IP_PROTO_INT = 253

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def handle_pkt(pkt, local_ip, iface):
    if IP in pkt and pkt[IP].proto == IP_PROTO_INT:
        
        raw_data = bytes(pkt[IP].payload)
        if len(raw_data) < 4:
            return

        # 1. Extrai o Master Header
        next_proto, num_slave, int_length = struct.unpack("!BBH", raw_data[:4])
        
        hops_data = []
        offset = 4
        for i in range(num_slave):
            # AGORA O SLAVE TEM 12 BYTES (adicionamos os 4 bytes do packet_length)
            if offset + 12 > len(raw_data):
                break
            
            # !HBBII = Short(2) + Char(1) + Char(1) + Int(4) + Int(4) = 12 Bytes
            sw_id, in_port, eg_port, ts, pkt_len = struct.unpack("!HBBII", raw_data[offset:offset+12])
            hops_data.append((sw_id, in_port, eg_port, ts, pkt_len))
            offset += 12
            
        original_payload = raw_data[int_length:]
        mensagem_app = "Nenhuma mensagem legivel encontrada."
        proto_nome = "Desconhecido"
        
        if next_proto == 6:
            proto_nome = "TCP (6)"
            tcp_layer = TCP(original_payload)
            if tcp_layer.haslayer(Raw):
                mensagem_app = tcp_layer[Raw].load.decode('utf-8', errors='ignore')
        elif next_proto == 17:
            proto_nome = "UDP (17)"
            udp_layer = UDP(original_payload)
            if udp_layer.haslayer(Raw):
                mensagem_app = udp_layer[Raw].load.decode('utf-8', errors='ignore')

        # INTERFACE TUI TOTALMENTE LIMPA E EXPANDIDA
        clear_screen()
        print("╔══════════════════════════════════════════════════════════════════════════╗")
        print("║                   DASHBOARD DE TELEMETRIA INT (P4)                       ║")
        print("╠══════════════════════════════════════════════════════════════════════════╣")
        print(f"║ Interface: {iface:<12} │ IP Local: {local_ip:<39} ║")
        print("╠══════════════════════════════════════════════════════════════════════════╣")
        print(f"║ Fluxo:         {pkt[IP].src}  -->  {pkt[IP].dst}")
        print(f"║ Protocolo:     {proto_nome}")
        print(f"║ INT Header:    {int_length} bytes de telemetria acumulada")
        print(f"║ Mensagem:      \"{mensagem_app}\"")
        print("╠══════════════════════════════════════════════════════════════════════════╣")
        print("║ SALTO │ SW ID │ IN │ OUT │ TIMESTAMP (us)       │ TAMANHO PACOTE (Bytes) ║")
        print("╟───────┼───────┼────┼─────┼──────────────────────┼────────────────────────╢")
        
        for i, hop in enumerate(hops_data):
            # Formatado matematicamente para encaixar exatos 76 caracteres na tela
            print(f"║  {i+1:02d}   │  {hop[0]:<5}│ {hop[1]:<3}│  {hop[2]:<3}│ {hop[3]:<21}│ {hop[4]:<23}║")
            
        print("╚══════════════════════════════════════════════════════════════════════════╝")
        print("  Aguardando novos pacotes de telemetria... (Ctrl+C para sair)")

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    if not ifaces:
        print("Nenhuma interface 'eth' encontrada.")
        sys.exit(1)
        
    iface = ifaces[0]
    local_ip = get_if_addr(iface)
    
    clear_screen()
    print("==========================================================================")
    print(f" Inicializando Receptor INT no IP {local_ip} (Interface {iface})")
    print(" Aguardando pacotes de aplicacao...")
    print("==========================================================================")
    
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x, local_ip, iface))

if __name__ == '__main__':
    main()