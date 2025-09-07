#!/usr/bin/env python3
import argparse
import os
import time
import re
import base64
import zlib
from collections import defaultdict
from scapy.all import *

class StealthReceiver:
    def __init__(self, args):
        self.args = args
        self.file_buffers = defaultdict(bytes)
        self.file_metadata = {}
        self.received_chunks = defaultdict(set)
        self.running = True
        self.interface = args.interface
        self.output_dir = args.output_dir
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"Created output directory: {self.output_dir}")
            
        print(f"🕵️  Stealth Receiver on {self.interface}")
        print(f"💾 Output directory: {os.path.abspath(self.output_dir)}")
        print(f"🔓 Obfuscation modes: All supported")
        print("📡 Listening for files and messages...")
        print("-" * 50)

    def decode_payload(self, payload, obfuscation_mode):
        """Decode payload based on obfuscation mode"""
        try:
            if obfuscation_mode == "none":
                return payload
            elif obfuscation_mode == "base64":
                return base64.b64decode(payload)
            elif obfuscation_mode == "compression":
                return zlib.decompress(payload)
            elif obfuscation_mode == "xor":
                # Simple XOR decryption with a fixed key
                key = b'covert'
                return bytes([b ^ key[i % len(key)] for i, b in enumerate(payload)])
            else:
                return payload
        except Exception as e:
            if self.args.verbose:
                print(f"[DEBUG] Decoding error: {e}")
            return None

    def strip_obfuscation(self, payload):
        """Remove stealth obfuscation to extract real payload"""
        try:
            if isinstance(payload, bytes):
                # Look for our clear separator in bytes
                separator = b'COVERT|'
                if separator in payload:
                    parts = payload.split(separator, 1)
                    if len(parts) > 1:
                        return parts[1]
            
            return payload
            
        except Exception as e:
            if self.args.verbose:
                print(f"[DEBUG] Obfuscation strip error: {e}")
            return None

    def process_packet(self, packet):
        """Process incoming packets"""
        try:
            if packet.haslayer(IP) and packet[IP].proto in [41, 47, 50, 51]:
                ip_layer = packet[IP]
                
                if packet.haslayer(Raw):
                    raw_payload = packet[Raw].load
                    src_ip = ip_layer.src
                    
                    # Remove obfuscation
                    clean_payload = self.strip_obfuscation(raw_payload)
                    if not clean_payload:
                        return
                    
                    if self.args.verbose:
                        print(f"[DEBUG] From {src_ip}: {clean_payload[:100]}...")
                    
                    # Check if it's a message (starts with MSG:)
                    try:
                        if clean_payload.startswith(b'MSG:'):
                            payload_str = clean_payload.decode('utf-8', errors='ignore')
                            self.handle_message(payload_str, src_ip)
                            return
                    except:
                        pass
                    
                    # Check if it's a file chunk (starts with FILE:)
                    try:
                        if clean_payload.startswith(b'FILE:'):
                            self.handle_file_chunk(clean_payload, src_ip)
                    except Exception as e:
                        if self.args.verbose:
                            print(f"[DEBUG] File processing error: {e}")
                        
        except Exception as e:
            if self.args.verbose:
                print(f"[DEBUG] Packet processing error: {e}")

    def handle_message(self, payload, src_ip):
        """Handle text messages"""
        try:
            parts = payload.split(':', 3)
            if len(parts) >= 4:
                msg_type, seq_num, timestamp, message = parts
                timestamp_str = time.strftime('%H:%M:%S', time.localtime(int(timestamp)))
                print(f"\n📨 [{timestamp_str}] {src_ip}: {message}")
                
        except Exception as e:
            if self.args.verbose:
                print(f"[DEBUG] Message error: {e}")

    def handle_file_chunk(self, raw_payload, src_ip):
        """Handle file chunks"""
        try:
            # Find the end of the header (after the fourth colon)
            first_colon = raw_payload.find(b':') + 1
            second_colon = raw_payload.find(b':', first_colon) + 1
            third_colon = raw_payload.find(b':', second_colon) + 1
            fourth_colon = raw_payload.find(b':', third_colon) + 1
            fifth_colon = raw_payload.find(b':', fourth_colon) + 1
            
            if first_colon == 0 or second_colon == 0 or third_colon == 0 or fourth_colon == 0:
                if self.args.verbose:
                    print("[DEBUG] Invalid FILE format: not enough colons")
                return
                
            # Extract the header part
            header_part = raw_payload[:fifth_colon].decode('utf-8', errors='ignore')
            
            # Use regex to reliably extract metadata
            file_pattern = r'FILE:([^:]+):(\d+):(\d+):([^:]+):'
            match = re.search(file_pattern, header_part)
            
            if not match:
                if self.args.verbose:
                    print(f"[DEBUG] Invalid FILE format: {header_part}")
                return
            
            filename = match.group(1)
            try:
                chunk_num = int(match.group(2))
                total_chunks = int(match.group(3))
                obfuscation_mode = match.group(4)
            except ValueError:
                if self.args.verbose:
                    print(f"[DEBUG] Invalid chunk numbers")
                return
            
            # Extract the binary data (after the header)
            chunk_data = raw_payload[fifth_colon:]
            
            # Decode the chunk data based on obfuscation mode
            decoded_data = self.decode_payload(chunk_data, obfuscation_mode)
            if decoded_data is None:
                if self.args.verbose:
                    print(f"[DEBUG] Failed to decode chunk {chunk_num} with mode {obfuscation_mode}")
                return
            
            file_key = f"{src_ip}_{filename}"
            
            # Initialize file metadata if this is the first chunk
            if file_key not in self.file_metadata:
                self.file_metadata[file_key] = {
                    'filename': filename,
                    'total_chunks': total_chunks,
                    'src_ip': src_ip,
                    'obfuscation_mode': obfuscation_mode,
                    'start_time': time.time(),
                    'expected_size': 0
                }
                print(f"\n📁 Receiving file: {filename} ({total_chunks} chunks)")
                print(f"   Obfuscation: {obfuscation_mode}")
            
            # Store chunk data if we haven't received it yet
            if chunk_num not in self.received_chunks[file_key]:
                self.file_buffers[file_key] += decoded_data
                self.received_chunks[file_key].add(chunk_num)
                
                received = len(self.received_chunks[file_key])
                total = self.file_metadata[file_key]['total_chunks']
                
                # Show progress every 5 chunks or when complete
                if received % 5 == 0 or received == total:
                    progress = (received / total) * 100
                    print(f"📦 Progress: {progress:.1f}% ({received}/{total})")
                
                # Check if we have all chunks
                if received >= total:
                    self.save_complete_file(file_key)
                    
        except Exception as e:
            if self.args.verbose:
                print(f"[DEBUG] File chunk error: {e}")
            import traceback
            traceback.print_exc()

    def save_complete_file(self, file_key):
        """Save completed file with proper error handling"""
        try:
            if file_key not in self.file_metadata or file_key not in self.file_buffers:
                if self.args.verbose:
                    print(f"[DEBUG] Missing file data for {file_key}")
                return
                
            metadata = self.file_metadata[file_key]
            file_data = self.file_buffers[file_key]
            filename = metadata['filename']
            
            # Create safe filename
            safe_filename = "".join(c for c in filename if c.isalnum() or c in '._- ').rstrip()
            if not safe_filename:
                safe_filename = f"received_file_{int(time.time())}"
                
            file_path = os.path.join(self.output_dir, safe_filename)
            
            # Ensure we don't overwrite existing files
            counter = 1
            original_path = file_path
            while os.path.exists(file_path):
                name, ext = os.path.splitext(original_path)
                file_path = f"{name}_{counter}{ext}"
                counter += 1
            
            # Write the file
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            file_size = len(file_data)
            transfer_time = time.time() - metadata['start_time']
            speed = file_size / transfer_time / 1024  # KB/s
            
            print(f"\n✅ File received: {safe_filename}")
            print(f"   Size: {file_size} bytes")
            print(f"   Time: {transfer_time:.1f}s")
            print(f"   Speed: {speed:.1f} KB/s")
            print(f"   Obfuscation: {metadata['obfuscation_mode']}")
            print(f"   Saved to: {os.path.abspath(file_path)}")
            
            # Verify file was actually written
            if os.path.exists(file_path):
                actual_size = os.path.getsize(file_path)
                if actual_size == file_size:
                    print(f"   ✓ File verified: {actual_size} bytes on disk")
                else:
                    print(f"   ⚠️ Size mismatch: expected {file_size}, got {actual_size}")
            else:
                print("   ❌ ERROR: File was not created!")
            
            # Clean up
            self.cleanup_file(file_key)
            
        except Exception as e:
            print(f"\n[!] Error saving file {file_key}: {e}")
            import traceback
            traceback.print_exc()

    def cleanup_file(self, file_key):
        """Clean up file resources"""
        try:
            if file_key in self.file_buffers:
                del self.file_buffers[file_key]
            if file_key in self.file_metadata:
                del self.file_metadata[file_key]
            if file_key in self.received_chunks:
                del self.received_chunks[file_key]
        except:
            pass

    def start_receiver(self):
        """Main receiver loop"""
        print("Press Ctrl+C to stop...")
        print(f"Watching folder: {os.path.abspath(self.output_dir)}")
        
        protocol_filter = " or ".join([f"ip proto {p}" for p in [41, 47, 50, 51]])
        
        try:
            sniff(
                iface=self.args.interface, 
                filter=protocol_filter,
                prn=self.process_packet, 
                store=0,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\n🛑 Receiver stopped.")
        except Exception as e:
            print(f"[!] Sniffing error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Stealth File/Message Receiver')
    
    parser.add_argument('-i', '--interface', required=True, help='Network interface (e.g., eth0, wlan0, lo)')
    parser.add_argument('-o', '--output-dir', default='received_files', help='Output directory for files')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    receiver = StealthReceiver(args)
    receiver.start_receiver()

if __name__ == "__main__":
    main()
