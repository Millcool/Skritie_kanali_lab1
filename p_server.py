import socket
import os

SERVER_ADDRESS = ('localhost', 3162)
BUFFER = 30000
ALPHABET = 100


def attacker(data, max_len):
    packet_len = len(data) + 32
    print(f'packet_len:{packet_len}, chr_num:{(30 + (packet_len // (max_len // ALPHABET)))}')
    print(f' Получен символ:{(chr(30 + (packet_len // (max_len // ALPHABET))))}')
    return (chr(30 + (packet_len // (max_len // ALPHABET))))


def get_max_len(data):
    print(f'Первый пакет получен сервером. Максимальная длина пакета: {len(data)}')
    return (len(data))


def get_file_len(data):
    file_len = data.count(b'\x00')
    print(f'Второй пакет получен сервером. Длина сообщения равна: {file_len}')
    return (file_len)


def server_program():
    string = ''
    count = 0
    file_len = 2
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(SERVER_ADDRESS)
    f = open('result.txt', 'w')
    try:
        while True:
            data, adress = server_socket.recvfrom(BUFFER)
            if not data:
                break
            elif count == 0:
                max_len = get_max_len(data)
            elif count == 1:
                file_len = get_file_len(data)
            elif count <= file_len+1:
                letter = attacker(data, max_len)
                string += letter
                try:
                    f.write(letter)
                except UnicodeEncodeError:
                    print('Данный символ нельзя записать')
                if count == file_len+1:
                    f.close()
                print(f'Текущее собщение: {string}')
            print(f'// От пользователя: {adress[0]}, сообщение:' + data.decode('utf-8') + ' //\n')
            print('--------------------------------------------')
            count += 1
    except KeyboardInterrupt:
        os.system('PAUSE')



if __name__ == '__main__':
    server_program()
