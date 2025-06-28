import socket
import threading
import time
import json
import logging
import argparse
from datetime import datetime
from collections import defaultdict, deque
import re
import struct

class SimpleIDS:
    def __init__(self, interface='eth0', log_file='ids.log'):
        self.interface = interface
        self.log_file = log_file
        self.running = False
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        self.connection_count = defaultdict(int)
        self.request_history = defaultdict(lambda: deque(maxlen=100))
        self.blocked_ips = set()

        self.rules = self.load_rules()

        self.stats = {
            'total_packets': 0,
            'suspicious_packets': 0,
            'blocked_connections': 0,
            'start_time': None
        }
        
    def load_rules(self):
        rules = {
            'port_scan_threshold': 10,  
            'request_rate_threshold': 50, 
            'suspicious_ports': [22, 23, 135, 139, 445, 1433, 3306, 3389],
            'malicious_patterns': [
                r'(?i)(union.*select|drop.*table|insert.*into)', 
                r'(?i)(<script|javascript:|vbscript:)',  
                r'(?i)(\.\.\/|\.\.\\)',  
                r'(?i)(eval\(|exec\(|system\()', 
                r'(?i)(wget|curl).*http',  
            ],
            'blacklisted_ips': [
                '192.168.1.100', 
            ]
        }
        return rules
    
    def create_raw_socket(self):
        """Create raw socket for packet capture"""
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_socket.bind(('0.0.0.0', 0))
            raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            return raw_socket
        except PermissionError:
            self.logger.error("Permission denied. Run as root/administrator for raw socket access.")
            return None
        except Exception as e:
            self.logger.error(f"Failed to create raw socket: {e}")
            return None
    
    def parse_ip_header(self, packet):
        try:
            ip_header = packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            iph_length = ihl * 4
            
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dest_addr = socket.inet_ntoa(iph[9])
            
            return {
                'version': version,
                'header_length': iph_length,
                'protocol': protocol,
                'src_ip': src_addr,
                'dest_ip': dest_addr,
                'packet': packet
            }
        except Exception as e:
            self.logger.debug(f"Error parsing IP header: {e}")
            return None
    
    def parse_tcp_header(self, packet, ip_header_length):
        try:
            tcp_header = packet[ip_header_length:ip_header_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            src_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = (doff_reserved >> 4) * 4
            
            flags = tcph[5]
            syn_flag = flags & 0x02
            ack_flag = flags & 0x10
            fin_flag = flags & 0x01
            rst_flag = flags & 0x04
            
            return {
                'src_port': src_port,
                'dest_port': dest_port,
                'sequence': sequence,
                'acknowledgement': acknowledgement,
                'header_length': tcph_length,
                'flags': {
                    'syn': bool(syn_flag),
                    'ack': bool(ack_flag),
                    'fin': bool(fin_flag),
                    'rst': bool(rst_flag)
                }
            }
        except Exception as e:
            self.logger.debug(f"Error parsing TCP header: {e}")
            return None
    
    def extract_payload(self, packet, ip_header_length, tcp_header_length):
        try:
            header_size = ip_header_length + tcp_header_length
            payload = packet[header_size:]
            return payload.decode('utf-8', errors='ignore')
        except Exception as e:
            self.logger.debug(f"Error extracting payload: {e}")
            return ""
    
    def detect_port_scan(self, src_ip, dest_port):
        current_time = time.time()

        self.request_history[src_ip] = deque([
            timestamp for timestamp in self.request_history[src_ip]
            if current_time - timestamp < 60
        ], maxlen=100)

        self.request_history[src_ip].append(current_time)
        if len(self.request_history[src_ip]) > self.rules['port_scan_threshold']:
            return True
        
        return False
    
    def detect_malicious_payload(self, payload):
        for pattern in self.rules['malicious_patterns']:
            if re.search(pattern, payload):
                return pattern
        return None
    
    def is_suspicious_port(self, port):
        return port in self.rules['suspicious_ports']
    
    def is_blacklisted_ip(self, ip):
        return ip in self.rules['blacklisted_ips']
    
    def log_suspicious_activity(self, activity_type, details):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': activity_type,
            'details': details,
            'severity': self.get_severity(activity_type)
        }
        
        self.logger.warning(f"ALERT: {activity_type} - {details}")
        self.stats['suspicious_packets'] += 1
        
        if alert['severity'] == 'HIGH':
            src_ip = details.get('src_ip')
            if src_ip:
                self.blocked_ips.add(src_ip)
                self.stats['blocked_connections'] += 1
    
    def get_severity(self, activity_type):
        high_severity = ['SQL_INJECTION', 'XSS_ATTEMPT', 'CODE_INJECTION', 'BLACKLISTED_IP']
        medium_severity = ['PORT_SCAN', 'DIRECTORY_TRAVERSAL', 'SUSPICIOUS_PORT']
        
        if activity_type in high_severity:
            return 'HIGH'
        elif activity_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def process_packet(self, packet):
        self.stats['total_packets'] += 1

        ip_info = self.parse_ip_header(packet)
        if not ip_info or ip_info['protocol'] != 6:  
            return
        
        src_ip = ip_info['src_ip']
        dest_ip = ip_info['dest_ip']

        if self.is_blacklisted_ip(src_ip):
            self.log_suspicious_activity('BLACKLISTED_IP', {
                'src_ip': src_ip,
                'dest_ip': dest_ip
            })
            return
        
        if src_ip in self.blocked_ips:
            return
        tcp_info = self.parse_tcp_header(packet, ip_info['header_length'])
        if not tcp_info:
            return
        
        src_port = tcp_info['src_port']
        dest_port = tcp_info['dest_port']

        if self.detect_port_scan(src_ip, dest_port):
            self.log_suspicious_activity('PORT_SCAN', {
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'connection_count': len(self.request_history[src_ip])
            })

        if self.is_suspicious_port(dest_port):
            self.log_suspicious_activity('SUSPICIOUS_PORT', {
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'port': dest_port
            })

        payload = self.extract_payload(packet, ip_info['header_length'], tcp_info['header_length'])
        if payload:
            malicious_pattern = self.detect_malicious_payload(payload)
            if malicious_pattern:
                activity_type = self.classify_attack(malicious_pattern)
                self.log_suspicious_activity(activity_type, {
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'pattern': malicious_pattern,
                    'payload_snippet': payload[:100]
                })
    
    def classify_attack(self, pattern):
        if 'union.*select' in pattern.lower() or 'drop.*table' in pattern.lower():
            return 'SQL_INJECTION'
        elif 'script' in pattern.lower() or 'javascript' in pattern.lower():
            return 'XSS_ATTEMPT'
        elif '..' in pattern:
            return 'DIRECTORY_TRAVERSAL'
        elif 'eval(' in pattern.lower() or 'exec(' in pattern.lower():
            return 'CODE_INJECTION'
        elif 'wget' in pattern.lower() or 'curl' in pattern.lower():
            return 'COMMAND_INJECTION'
        else:
            return 'MALICIOUS_PATTERN'
    
    def packet_capture_thread(self):
        raw_socket = self.create_raw_socket()
        if not raw_socket:
            self.logger.error("Cannot create raw socket. Exiting.")
            return
        
        self.logger.info("Starting packet capture...")
        self.stats['start_time'] = datetime.now()
        
        try:
            while self.running:
                packet = raw_socket.recvfrom(65565)[0]
                self.process_packet(packet)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
        finally:
            raw_socket.close()
    
    def stats_thread(self):
        while self.running:
            time.sleep(60)  
            if self.stats['start_time']:
                uptime = datetime.now() - self.stats['start_time']
                self.logger.info(f"Krips IDS - Uptime: {uptime}, "
                               f"Total packets: {self.stats['total_packets']}, "
                               f"Suspicious: {self.stats['suspicious_packets']}, "
                               f"Blocked IPs: {len(self.blocked_ips)}")
    
    def start(self):
        self.running = True
        self.logger.info("simple id starting... (((krips)))")

        capture_thread = threading.Thread(target=self.packet_capture_thread)
        capture_thread.daemon = True
        capture_thread.start()
        stats_thread = threading.Thread(target=self.stats_thread)
        stats_thread.daemon = True
        stats_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        self.logger.info("simple ids stopping... (((krips)))")
        self.running = False

        if self.stats['start_time']:
            uptime = datetime.now() - self.stats['start_time']
            self.logger.info(f"Final Stats - Uptime: {uptime}, "
                           f"Total packets: {self.stats['total_packets']}, "
                           f"Suspicious packets: {self.stats['suspicious_packets']}, "
                           f"Blocked IPs: {len(self.blocked_ips)}")

def main():
    parser = argparse.ArgumentParser(description='Simple Intrusion Detection')
    parser.add_argument('-i', '--interface', default='eth0', 
                       help='Network interface to monitor (default: eth0)')
    parser.add_argument('-l', '--log', default='ids.log',
                       help='Log file path (default: ids.log)')
    
    args = parser.parse_args()
    
    ids = SimpleIDS(interface=args.interface, log_file=args.log)
    
    try:
        ids.start()
    except Exception as e:
        print(f"Error starting ids supporter contact (krips): {e}")

if __name__ == "__main__":
    main()