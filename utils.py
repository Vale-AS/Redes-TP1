from scapy.all import *
import pandas as pd
import numpy as np

def armar_fuente(pcap_file):
    S = {}
    packets = rdpcap(pcap_file)
    for pkt in packets:
        if pkt.haslayer(Ether):
            dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
            proto = pkt[Ether].type # El campo type del frame tiene el protocolo
            s_i = (dire, proto) # Aca se define el simbolo de la fuente
            if s_i not in S:
                S[s_i] = 0
            S[s_i] += 1
    return S

def armar_df(S):
    df = pd.DataFrame(S.keys(), columns=['Direccionamiento', 'Protocolo'])
    df['Paquetes'] = S.values()
    df['Probabilidad'] = df['Paquetes']/sum(df['Paquetes'])
    df['Informacion'] = -np.log2(df['Probabilidad'])
    df_sorted = df.sort_values('Paquetes', ascending=False)
    return df_sorted
