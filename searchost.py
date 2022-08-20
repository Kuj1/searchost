#!/usr/bin/env python3

import os
import platform
import time
import logging
from socket import gaierror
from subprocess import check_output

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import scapy.all as sc
import requests
import lxml
from pyfiglet import Figlet
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich.text import Text

result = dict()
net_masks = dict()

url = 'https://www.pawprint.net/designresources/netmask-converter.php'


def get_decoded_net_mask(url: str = url) -> dict:
    response = requests.get(url)
    
    soup = BeautifulSoup(response.text, features='xml')
    
    table_mask = soup.find('table', class_='info').find_all('tr')[1:-1]
    
    for mask in table_mask:
        splited_mask = mask.find_all('td')
        decode, encode = splited_mask[0].get_text().strip(), splited_mask[2].get_text().strip()
        net_masks[encode] = decode

    return net_masks

def get_net_mask():
    if platform.system() == 'Darwin':
        net_mask = str(check_output("ifconfig en0 | grep 'netmask'", shell=True).decode()).split()[3].strip()
        for k, v in get_decoded_net_mask().items():
            if k == net_mask:

                 return int(v.replace('/',''))
    elif platform.system() == 'Linux':
        net_mask = str(check_output('ip -h -br a  | grep UP', shell=True).decode()).split()[2].split("/")[1]

        return net_mask


def get_ip_mac_nework(ip):
    answered_list = sc.srp(sc.Ether(dst='ff:ff:ff:ff:ff:ff') / sc.ARP(pdst=ip), timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        clients_list.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
    return clients_list


def syn_ack_scan(ip, ports):
    try:
        request_syn = sc.IP(dst=ip) / sc.TCP(dport=ports, flags="S")
    except gaierror:
        raise ValueError(f'Failed to get{ip}')
    answer = sc.sr(request_syn, timeout=1, retry=1, verbose=False)[0]

    for send, receiv in answer:
        if receiv['TCP'].flags == "SA":
            try:
                if str(receiv['IP'].src) not in result:
                    result[str(receiv['IP'].src)] = dict()
                if str(receiv['TCP'].sport) not in result[str(receiv['IP'].src)]:
                    result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = dict()
                if str(sc.TCP_SERVICES[receiv['TCP'].sport]) not in result[str(receiv['IP'].src)] \
                        [str(receiv['TCP'].sport)]:
                    result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = str(sc.TCP_SERVICES[receiv['TCP'].sport])
            except KeyError:
                result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = 'Undefined'


def print_port(ip_mac_network):
    list_data_table = []
    table = Table(title='\t\t  *Network Information (IP, MAC) // Open Port*',
                  title_justify='left')
    table.add_column('IP', no_wrap=False, justify='left', style='green')
    table.add_column('MAC', no_wrap=False, justify='left', style='green')
    table.add_column('Ports', no_wrap=False, justify='left', style='green')

    for ip in ip_mac_network:
        list_data_table.append(ip['ip'])
        list_data_table.append(ip['mac'])
        if ip['ip'] in result:
            list_data_table.append(str(result[ip['ip']]).replace("': '", '/').replace('{', '[').replace('}',']'))
        else:
            list_data_table.append(" --- ")

        table.add_row(list_data_table[0], list_data_table[1], list_data_table[2])
        list_data_table = []
    console = Console()
    print(' ')
    console.print(table)


def main():
    console = Console()
    title_main = Figlet(font='isometric4',justify="center")
    print(title_main.renderText(f'SEARCHOST'))
    start = time.monotonic()
    if not os.getuid() == 0:
        text = Text("\n [!] Run the script as root user!")
        text.stylize('bold red')
        console.print(text)
        return

    user_invitation = Text('Please enter ports range (separated by a space)\nExample: "1 1024" or "1024"\n ')
    user_invitation.stylize('bold yellow')
    console.print(user_invitation)

    users_range = input('>> ').split()

    if len(users_range) == 1:
        users_range.insert(0, 1)

    port_range = tuple(map(int, users_range))
    local_ip = sc.conf.route.route('0.0.0.0')[1]
    ip_mac_network = get_ip_mac_nework(f'{local_ip}/{get_net_mask()}')

    with Progress() as progress:
        task = progress.add_task('[green]Scaning...', total=len(ip_mac_network))
        for ip in ip_mac_network:
            syn_ack_scan(ip['ip'], port_range)
            progress.update(task, advance=1)

    print_port(ip_mac_network)
    text_title = Text(f'\n * Local IP: {local_ip}    * Local Gateway: {sc.conf.route.route("0.0.0.0")[2]}\n')
    text_title.stylize('bold')
    console.print(text_title)

    text_time = Text(f'Scan time: {time.monotonic() - start}')
    text_time.stylize('red')
    console.print(text_time)


if __name__ == "__main__":
    main()