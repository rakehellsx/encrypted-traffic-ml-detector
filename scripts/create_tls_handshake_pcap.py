#!/usr/bin/env python3
"""Create safe synthetic TLS ClientHello PCAPs for parser and pipeline regression only."""
import ipaddress, struct, sys, time

def ipv4_checksum(data):
    if len(data) % 2: data += b'\x00'
    total = sum(struct.unpack(f'!{len(data)//2}H', data))
    total = (total >> 16) + (total & 0xffff); total += total >> 16
    return (~total) & 0xffff

def client_hello(server_name, tls_version=0x0304):
    random = bytes(range(32)); ciphers = [0x1301,0x1302,0x1303,0xC02F]
    sni = server_name.encode(); sni_data = struct.pack('!H', len(sni)+3)+b'\x00'+struct.pack('!H',len(sni))+sni
    groups = struct.pack('!H',4)+struct.pack('!HH',0x001d,0x0017)
    formats = b'\x01\x00'
    versions = b'\x04\x03\x04\x03\x03'
    extensions = b''.join([struct.pack('!HH',0,len(sni_data))+sni_data, struct.pack('!HH',10,len(groups))+groups, struct.pack('!HH',11,len(formats))+formats, struct.pack('!HH',43,len(versions))+versions])
    body = struct.pack('!H',tls_version)+random+b'\x00'+struct.pack('!H',len(ciphers)*2)+b''.join(struct.pack('!H',x) for x in ciphers)+b'\x01\x00'+struct.pack('!H',len(extensions))+extensions
    handshake = b'\x01'+len(body).to_bytes(3,'big')+body
    return b'\x16\x03\x01'+struct.pack('!H',len(handshake))+handshake

def packet(src, dst, sport, dport, payload, seq, timestamp):
    eth=b'\x00'*12+b'\x08\x00'; ip_src=ipaddress.ip_address(src).packed; ip_dst=ipaddress.ip_address(dst).packed
    total=20+20+len(payload); ip0=struct.pack('!BBHHHBBH4s4s',0x45,0,total,1,0,64,6,0,ip_src,ip_dst); ip=ip0[:10]+struct.pack('!H',ipv4_checksum(ip0))+ip0[12:]
    tcp=struct.pack('!HHLLBBHHH',sport,dport,seq,0,0x50,0x18,8192,0,0)
    return struct.pack('<IIII',int(timestamp),0,len(eth+ip+tcp+payload),len(eth+ip+tcp+payload))+eth+ip+tcp+payload

out=sys.argv[1] if len(sys.argv)>1 else '/home/ubuntu/Downloads/synthetic-tls-handshakes.pcap'
records=[]; now=int(time.time())
for i,(sni,version) in enumerate([('benign.example.test',0x0304),('control.example.test',0x0304),('transfer.example.test',0x0303)]):
    payload=client_hello(sni,version); records.append(packet(f'10.0.0.{10+i}','203.0.113.10',40000+i,443,payload,1000+i,now+i))
with open(out,'wb') as f: f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+b''.join(records))
print(out)
