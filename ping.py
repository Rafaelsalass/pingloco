import subprocess
import ipaddress
import socket
import fcntl
import struct
import re
import codecs
from subprocess import Popen, PIPE
from netaddr import IPNetwork
from multiping import MultiPing

ip = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]
proc = subprocess.Popen(['ifconfig'],stdout=subprocess.PIPE)

while True:
    line = proc.stdout.readline()
    if ip.encode() in line:
        break
mask = line.rstrip().lstrip().split(' '.encode())[4]
hostAndMask = str(IPNetwork(ip + '/' + mask.decode()).cidr)
host = ipaddress.IPv4Address(ip)
net = ipaddress.IPv4Network(hostAndMask, False)
subnet = ipaddress.IPv4Address(int(host) & int(net.netmask))
broadcast = net.broadcast_address

# hostAndMask = '10.0.10.0/24'

print('ip:', ip)
print('mascara:', mask.decode())
print('ip y mascara:', hostAndMask)
print('ip de red:', subnet)
print('broadcast:', broadcast)

network = ipaddress.ip_network(hostAndMask)
print('obteniendo lista de host activos en la red...')
aliveHosts = []
hosts = list(network.hosts())
hosts = hosts[100:106]
print(len(hosts))
for i in hosts:
    i = str(i)
    toping = Popen(['ping', '-c', '1', i], stdout=PIPE)
    output = toping.communicate()[0]
    hostalive = toping.returncode

    if hostalive == 0:
        print(i, 'esta activo')
        aliveHosts.append(i)

text = codecs.encode('virus'.encode(), 'hex_codec')
for i in aliveHosts:
    i = str(i)
    toping = Popen(['ping', '-c', '1', '-p', text.decode(), i], stdout=PIPE)
    output = toping.communicate()[0]

def listen():
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    while 1:
        recPacket, addr = s.recvfrom(1024)
        icmp_header = recPacket[20:28]
        type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
        print(addr)
        print("type: [" + str(type) + "] code: [" + str(code) + "] checksum: [" + str(checksum) + "] p_id: [" + str(p_id) + "] sequence: [" + str(sequence) + "]")

listen()
