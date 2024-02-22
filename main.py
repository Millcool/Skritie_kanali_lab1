import socket
import threading
import bitarray
import argparse
import queue
from scapy.all import *
from scapy.layers.inet import *

SECOND_CLIENT_ADDRESS = ('::1', 65012, 0, 0)
FIRST_CLIENT_ADDRESS = ('::1', 65011, 0, 0)
PROXY_ADDRESS = ('::1', 65010, 0, 0)


# Имитация сетевого экрана
def listener():
    soc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    soc.bind(PROXY_ADDRESS)
    while True:
        data, address = soc.recvfrom(1024)
        if address[1] == 65011:
            soc.sendto(data, SECOND_CLIENT_ADDRESS)
        if address[1] == 65012:
            soc.sendto(data, FIRST_CLIENT_ADDRESS)


class MyConcurrentCollection:
    def __init__(self):
        self.collection = queue.Queue()

    def append(self, x):
        self.collection.put(x)

    def pop(self):
        return self.collection.get()

    def __len__(self):
        return self.collection.qsize()

    def __str__(self):
        return f"{len(self)}"

    def print_collection(self):
        return self.collection.queue

    def empty(self):
        return self.collection.empty()


class Worker(threading.Thread):
    def __init__(self, msg, input_collection: MyConcurrentCollection, callback=None):
        if not callback:
            raise NameError('callback not set')

        threading.Thread.__init__(self)
        self.daemon = True
        self.msg = msg
        self.input_collection = input_collection
        self.callback = callback

    def run(self):
        while True:
            if len(msg) == 0:
                print("Covert channel close, all message send")
                return

            if not self.input_collection.empty():
                print("Run sniff")
                packet = self.input_collection.pop()
                covert_message = msg[0]
                del msg[0]
                self.callback(covert_message, packet)
            else:
                time.sleep(0.1)


class Agent:
    def __init__(self, msg, callback=None, threads_count=1):
        self.col = MyConcurrentCollection()
        self.consumers = [Worker(msg, self.col, callback) for _ in range(threads_count)]

    def sniffer(self):
        print("run sniff")
        sniff(filter="src port 65011 and dst port 65010", prn=self.col.append, iface="lo")

    def run(self):
        for consumer in self.consumers:
            consumer.start()

        self.sniffer()

        for consumer in self.consumers:
            consumer.join()

    def agent_ttl(covert_message, pkt):
        if covert_message:
            ip_header = IP(src=pkt.getlayer(IP).src, dst=pkt.getlayer(IP).dst, ttl=20)
            udp_header = UDP(sport=pkt['UDP'].sport, dport=65012)
            packet_cov = ip_header / udp_header / pkt['UDP'].payload
            print("Send packet")
            send(packet_cov)
        else:
            ip_header = IP(src=pkt.getlayer(IP).src, dst=pkt.getlayer(IP).dst, ttl=200)
            udp_header = UDP(sport=pkt['UDP'].sport, dport=65012)
            packet_cov = ip_header / udp_header / pkt['UDP'].payload
            print("Send packet")
            send(packet_cov)


def agent_hop_limit(covert_message, pkt):
    if covert_message:
        ip_header = IPv6(src=pkt['IPv6'].src, dst='::1', hlim=15)
        udp_header = UDP(sport=pkt['UDP'].sport, dport=65012)
        packet_cov = ip_header / udp_header / pkt['UDP'].payload
        print("Send packet")
        send(packet_cov)
    else:
        ip_header = IPv6(src=pkt['IPv6'].src, dst='::1', hlim=100)
        udp_header = UDP(sport=pkt['UDP'].sport, dport=65012)
        packet_cov = ip_header / udp_header / pkt['UDP'].payload
        print("Send packet")
        send(packet_cov)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Covert channel emulation')
    parser.add_argument('-f', '--filename', help='data to tranfer via covert channel', required=False, dest='filename',
                        type=str)

    parser.add_argument('covert_mode', default='hop_limit', const='hop_limit', nargs='?', choices=['hop_limit'])
    args = parser.parse_args()
    if args.filename:
        file = open(args.filename)
        msg = file.read()
    else:
        msg = input()

    match args.covert_mode:
        case "hop_limit":
            ba = bitarray.bitarray()
            ba.frombytes(msg.encode('utf-8'))
            msg = ba.tolist()
            callback = agent_hop_limit

    agent = Agent(msg, callback)
    thread_agent = threading.Thread(target=agent.run, args=())
    thread_proxy = threading.Thread(target=listener, args=())

    thread_agent.start()
    thread_proxy.start()

    thread_agent.join()
    thread_proxy.join()
