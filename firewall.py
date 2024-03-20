import socket
import time
from random import randint
from scapy.all import *
from scapy.layers.inet import *

SERVER_ADDRESS = ('localhost', 3162)  # адрес сервера, куда посылаются сообщения
FIREWALL_ADDRESS = ('localhost', 3161)  # адрес средства защиты
CHANELL_ADDRESS = ('localhost', 3160)  # адрес закладки

BUFFER = 30000  # размер буфера для приема
ALPHABET = 100  # размер алфавита
NORMAL_LEN = 5000  # длина пакета для нормализации


# прослушка и отправка сообщений
def listener():
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.bind(FIREWALL_ADDRESS)
    count = 0
    while True:
        data, address = soc.recvfrom(BUFFER)
        # soc.sendto(data, SERVER_ADDRESS) #***
        channel_full_protect(count, data, address, soc)
        #channel_half_protect(count, data, address, soc)
        count += 1


# нейтрализация скрытого канала нормализацией длины
def channel_full_protect(count, data, address, soc):
    # первые 2 пакета обрабатываем отдельно
    if count <= 1:
        soc.sendto(data, SERVER_ADDRESS)
    else:
        if len(data) <= NORMAL_LEN:
            message = data + b'\x00' * (NORMAL_LEN - len(data))
            packet_creation(message, address)
        else:
            for _ in range(0, (len(data) // NORMAL_LEN) + 1):
                message = data[:NORMAL_LEN]
                data = data[NORMAL_LEN:]
                message += b'\x00' * (NORMAL_LEN - len(message))
                packet_creation(message, address)


# ограничения скрытого канала увеличением длины
def channel_half_protect(count, data, address, soc):
    if count <= 1:
        soc.sendto(data, SERVER_ADDRESS)
    else:
        message = get_message(data)
        packet_creation(message, address)


# получение нужного сообщения для отпарвки
def get_message(data):
    max_len = BUFFER - len(data)
    return (data + b'\x00' * randint(0, max_len))


# создание пакета
def packet_creation(message, address):
    ip_header = IP(src=address[0], dst=SERVER_ADDRESS[0])
    udp_header = UDP(sport=address[1], dport=SERVER_ADDRESS[1])
    res_packet = ip_header / udp_header / Raw(message)
    send(res_packet)
    time.sleep(0.1)


if __name__ == '__main__':
    listener()
