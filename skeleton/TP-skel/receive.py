#!/usr/bin/env python3
import os
import sys
from scapy.all import IP, sniff, hexdump

# Protocolo customizado definido no basic.p4
IP_PROTO_INT = 253 # 0xFD

def handle_pkt(pkt):
    # Verifica se o pacote tem a camada IP e usa o protocolo INT
    if IP in pkt and pkt[IP].proto == IP_PROTO_INT:
        print("\n" + "="*60)
        print("### [ PACOTE DE TELEMETRIA INT RECEBIDO ] ###")
        
        # O payload do IP contém o cabeçalho Master, a pilha de Slaves e o payload original
        raw_data = bytes(pkt[IP].payload)
        
        if len(raw_data) < 8:
            print("Aviso: Payload muito curto para conter o cabeçalho INT Master.")
            return

        # 1. Extração do Cabeçalho INT Master (8 bytes no total)
        # sizeSlave (32 bits = 4 bytes) | numSlave (32 bits = 4 bytes)
        size_slave = int.from_bytes(raw_data[0:4], byteorder='big')
        num_slave = int.from_bytes(raw_data[4:8], byteorder='big')
        
        print(f"MASTER HEADER -> Tamanho do Slave: {size_slave} bytes | Total de Saltos: {num_slave}")
        print("-" * 60)
        
        offset = 8
        
        # 2. Iteração sobre a pilha de cabeçalhos INT Slave
        for i in range(num_slave):
            if len(raw_data) < offset + size_slave:
                print(f"Erro: Dados truncados. Não foi possível ler o salto {i+1}.")
                break
                
            slave_data = raw_data[offset : offset + size_slave]
            
            # Extraindo os dados do slave com base no P4 (Total 24 bytes):
            # 0-4   (32 bits): switch_id
            # 4-8   (32 bits): ingress_port
            # 8-14  (48 bits): ingress_timestamp (Lido em 6 bytes)
            # 14-18 (32 bits): egress_port
            # 18-24 (48 bits): egress_timestamp  (Lido em 6 bytes)
            
            sw_id = int.from_bytes(slave_data[0:4], byteorder='big')
            in_port = int.from_bytes(slave_data[4:8], byteorder='big')
            in_ts = int.from_bytes(slave_data[8:14], byteorder='big')
            eg_port = int.from_bytes(slave_data[14:18], byteorder='big')
            eg_ts = int.from_bytes(slave_data[18:24], byteorder='big')
            
            print(f"  [Salto {i+1}] Switch ID: {sw_id}")
            print(f"      Porta de Entrada : {in_port} \t| Ingress Timestamp (us): {in_ts}")
            print(f"      Porta de Saída   : {eg_port} \t| Egress Timestamp (us) : {eg_ts}")
            
            offset += size_slave
            
        # 3. Exibindo o payload (mensagem) da aplicação
        original_payload = raw_data[offset:]
        print("-" * 60)
        try:
            # Tenta decodificar como texto puro (comportamento padrão do send.py)
            mensagem = original_payload.decode('utf-8')
            print(f"Mensagem da Aplicação: {mensagem}")
        except Exception:
            print("Payload Original (Hex/Binário):")
            hexdump(original_payload)
        
        print("="*60 + "\n")

def main():
    # Obtém as interfaces ethernet ativas no Mininet
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    if not ifaces:
        print("Nenhuma interface 'eth' encontrada para escuta.")
        sys.exit(1)
        
    iface = ifaces[0]
    print(f"Aguardando pacotes de telemetria na interface: {iface} ...")
    sys.stdout.flush()
    
    # Inicia a captura filtrando as requisições em tempo real
    sniff(iface=iface, prn=lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()