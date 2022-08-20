import os
import platform
import time
from socket import gaierror
from subprocess import check_output, CalledProcessError

import scapy.all as sc
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich.text import Text

result = dict()

# def get_net_mask():
#     if platform.system() == 'Darwin':
#         net_mask = str(check_output('ifconfig | grep netmask', shell=True).decode()).split()[3]
#         print(net_mask)
#     elif platform.system() == 'Linux':
#         pass

# get_net_mask()

# def get_ip_mac_nework(ip):
#     answered_list = sc.srp(sc.Ether(dst='ff:ff:ff:ff:ff:ff') / sc.ARP(pdst=ip), timeout=1, verbose=False)[0]
#     clients_list = []
#     for element in answered_list:
#         clients_list.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
#     return clients_list


# def syn_ack_scan(ip, ports):
#     try:
#         request_syn = sc.IP(dst=ip) / sc.TCP(dport=ports, flags="S")
#     except gaierror:
#         raise ValueError(f'{ip} получить не удалось')
#     answer = sc.sr(request_syn, timeout=2, retry=1, verbose=False)[0]

#     for send, receiv in answer:
#         if receiv['TCP'].flags == "SA":
#             try:
#                 if str(receiv['IP'].src) not in result:
#                     result[str(receiv['IP'].src)] = dict()
#                 if str(receiv['TCP'].sport) not in result[str(receiv['IP'].src)]:
#                     result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = dict()
#                 if str(sc.TCP_SERVICES[receiv['TCP'].sport]) not in result[str(receiv['IP'].src)] \
#                         [str(receiv['TCP'].sport)]:
#                     result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = str(sc.TCP_SERVICES[receiv['TCP'].sport])
#             except KeyError:
#                 result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = 'Undefined'


# def print_port(ip_mac_network):
#     list_data_table = []
#     table = Table(title='"Network Information (IP, MAC). Open Port Range (1-1024): "',
#                   title_justify='left')
#     table.add_column("IP", no_wrap=False, justify="left", style="green")
#     table.add_column("MAC", no_wrap=False, justify="left", style="green")
#     table.add_column("Ports", no_wrap=False, justify="left", style="green")

#     for ip in ip_mac_network:
#         list_data_table.append(ip['ip'])
#         list_data_table.append(ip['mac'])
#         if ip['ip'] in result:
#             list_data_table.append(str(result[ip['ip']]).replace("': '", "/").replace("{", "[").replace("}","]"))
#         else:
#             list_data_table.append(" --- ")

#         table.add_row(list_data_table[0], list_data_table[1], list_data_table[2], list_data_table[3])
#         list_data_table = []
#     console = Console()
#     print(' ')
#     console.print(table)


# def main():
#     start = time.monotonic()
#     if not os.getuid() == 0:
#         console = Console()
#         text = Text("\n [+] Run the script as root user!")
#         text.stylize("bold red")
#         console.print(text)
#         return
#     local_ip = sc.conf.route.route("0.0.0.0")[1]
#     ip_mac_network = get_ip_mac_nework(f'{local_ip}/{get_net_mask_linx()}')

#     # сканирование открытых портов
#     print(f'\n\n[+] Network scanning:\n{"-" * 21}')
#     netbios_dict = {}
#     with Progress() as progress:
#         task = progress.add_task("[green]Scaning...", total=len(ip_mac_network))
#         for ip in ip_mac_network:
#             syn_ack_scan(ip["ip"], (1, 1024))
#             name = netbios_check(ip["ip"])
#             if name:
#                 netbios_dict[ip["ip"]] = name
#             progress.update(task, advance=1)

#     # печать полученных данных
#     console = Console()
#     print_port(netbios_dict, ip_mac_network)
#     text = Text(f'\n [+] Local IP: {local_ip}    [+] Local Gateway: {sc.conf.route.route("0.0.0.0")[2]}\n')
#     text.stylize("bold")
#     console.print(text)

#     text = Text(f' [-] Scan time: {time.monotonic() - start}')
#     text.stylize("green")
#     console.print(text)


# if __name__ == "__main__":
#     main()