import pandas as pd
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Ether

def get_feature_names():
    # CICIoT23 Dataset ka exact column order (Total 46 features)
    return [
        'flow_duration', 'Header_Length', 'Protocol type', 'Duration', 'Rate', 'Srate', 
        'Drate', 'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 
        'ack_flag_number', 'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 
        'fin_count', 'urg_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 
        'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 
        'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 
        'Covariance', 'Variance', 'Weight'
    ]

def extract_packet_features(packet):
    feat_names = get_feature_names()
    # Baseline data (0.00 to avoid NaN)
    data = {f: 0.0 for f in feat_names}
    
    try:
        if IP in packet:
            data['IPv'] = 1.0
            data['Protocol type'] = float(packet[IP].proto)
            data['Header_Length'] = float(len(packet[IP]))
            data['Tot size'] = float(len(packet))
            data['Tot sum'] = float(len(packet))
            data['AVG'] = float(len(packet))
            data['Magnitue'] = np.sqrt(float(len(packet)))
            data['Weight'] = 1.0
            data['Rate'] = 1.0 # Default low rate
            
            # Protocol Detection
            if TCP in packet:
                data['TCP'] = 1.0
                flags = str(packet[TCP].flags)
                if 'S' in flags: 
                    data['syn_flag_number'] = 1.0
                    data['syn_count'] = 1.0
                if 'R' in flags: data['rst_flag_number'] = 1.0
                if 'F' in flags: data['fin_flag_number'] = 1.0
                if 'P' in flags: data['psh_flag_number'] = 1.0
                if 'A' in flags: data['ack_flag_number'] = 1.0
                
                # Common Port Mapping for Features
                if packet[TCP].dport == 80 or packet[TCP].sport == 80: data['HTTP'] = 1.0
                if packet[TCP].dport == 443 or packet[TCP].sport == 443: data['HTTPS'] = 1.0
                if packet[TCP].dport == 22 or packet[TCP].sport == 22: data['SSH'] = 1.0
                
            elif UDP in packet:
                data['UDP'] = 1.0
                if packet[UDP].dport == 53 or packet[UDP].sport == 53: data['DNS'] = 1.0
                
        if ICMP in packet:
            data['ICMP'] = 1.0
        
        if Ether in packet:
            # LLC/ARP detection
            if packet.type == 0x0806: data['ARP'] = 1.0

    except Exception as e:
        pass
        
    return pd.DataFrame([data], columns=feat_names)
