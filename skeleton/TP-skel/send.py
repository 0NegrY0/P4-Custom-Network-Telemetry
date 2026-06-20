#!/usr/bin/env python3
import os
import random
import socket
import sys

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp, get_if_addr


def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')


def get_if():
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Erro: Nao foi possivel encontrar a interface eth0")
        exit(1)
    return iface


def main():
    iface = get_if()
    local_ip = get_if_addr(iface)
    local_mac = get_if_hwaddr(iface)
    sport = random.randint(49152, 65535)
    dport = 1234

    # MODO INTERATIVO: Se nao passar os argumentos, ele pede na tela
    if len(sys.argv) < 3:
        clear_screen()
        print("╔══════════════════════════════════════════════════════════════════════╗")
        print("║                  ENVIO INTERATIVO DE PACOTES (P4)                    ║")
        print("╚══════════════════════════════════════════════════════════════════════╝")
        
        host_input = input(" Digite o host ou IP de destino: ").strip()
        mensagem = input(" Digite a mensagem que deseja enviar: ")
        
        if not host_input or not mensagem:
            print("\n Erro: O destino e a mensagem nao podem estar vazios.")
            exit(1)
    else:
        # MODO TRADICIONAL: Se passar por argumento no terminal
        host_input = sys.argv[1]
        mensagem = sys.argv[2]

    try:
        addr = socket.gethostbyname(host_input)
    except socket.gaierror:
        print(f"\n Erro: Nao foi possivel resolver o nome do host '{host_input}'")
        exit(1)

    # MONTACEM DO PACOTE (Identica a original)
    pkt = Ether(src=local_mac, dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr) / TCP(dport=dport, sport=sport) / mensagem
    
    sendp(pkt, iface=iface, verbose=False)

    # RENDERIZACAO DA TUI LIMPA
    clear_screen()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                  TRANSMISSOR DE PACOTES (P4-INT)                     ║")
    print("╠══════════════════════════════════════════════════════════════════════╣")
    print(f"║ Interface:     {iface:<12} │ IP Origem:        {local_ip:<17} ║")
    print(f"║ MAC Origem:    {local_mac:<12} │ Porta Origem:     {sport:<17} ║")
    print("╠══════════════════════════════════════════════════════════════════════╣")
    print(f"║ IP Destino:    {addr:<12} │ Porta Destino:    {dport:<17} ║")
    print(f"║ Mensagem/Txt:  \"{mensagem}\"")
    print("╠══════════════════════════════════════════════════════════════════════╣")
    print("║               PACOTE INJETADO NA REDE COM SUCESSO!                   ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")


if __name__ == '__main__':
    main()