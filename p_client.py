import socket
import argparse
import time
import string
import random

FIREWALL_ADDRESS = ('localhost', 2000)  # адрес средства защиты с закладкой
AMOUNT_OF_PACKET = 50                   # количество отправленных паетов, не считая первый

# функция передачи максимальной длины пакета
def parse_arguments():
    parser = argparse.ArgumentParser(description='Covert channel emulation')
    parser.add_argument('max_len', type=int, default=1024)
    #parser.add_argument('len', type=int, default=70)
    return parser.parse_args()

# функция генерации рандомной строки
def generate_random_string(length):
    letters = string.ascii_lowercase
    rand_string = ''.join(random.choice(letters) for i in range(length))
    return(rand_string)

#сама функция отправки пакетов
def client_program(m_len):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.connect((FIREWALL_ADDRESS))       # подключение к серверу
    message = 'First message'

    # отправка первого сообщения с максимальной длиной
    client_socket.send(message.encode() + b'\x00'*(m_len-len(message)))
    time.sleep(0.3)

    for i in range(AMOUNT_OF_PACKET):
        length = 20
        message = generate_random_string(length)    # пакет, для простоты, содержит рандомные символы в количестве длины пакета
        print(f'Отправлен {i} пакет длинной {length}')
        print(f'        Сообщение: {message}')
        client_socket.send(message.encode())
        time.sleep(0.3)                             # небольшая задержка, чтобы пакеты приходили ~ через 0.3 секунды
    client_socket.close()


if __name__ == '__main__':
    args = parse_arguments()
    client_program(args.max_len)
