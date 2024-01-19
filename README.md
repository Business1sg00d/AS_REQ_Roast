# AS_REQ_Roast

AS_REQ Roasting is an Active Directory attack vector where an attacker has root/Administrative access to a device that sits between the Kerberos client and server. If the victim authenticates via Kerberos, the attacker can capture the AS_REQ packet which contains cipher data that when parsed properly can be fed into hashcat. When successfully cracked, the clear text password of the victim is attained; lateral movement or privilege escalation can be performed. 

This tool takes a pcap file and looks for these AS_REQ packets. Once found, it extracts the data to form a hashcat readable hash for cracking. There are other tools that do this, but I didn't have any luck with getting them to work properly. Hence why I created this. 




# TODO

1. Add different encTypes; need further testing.




# Requirements

```
pip3 install scapy
```

A Virtual Environment is recommended.




# Usage

```
python3 as_req_roast.py [pcap file] [FQDN]

no brackets
```




# References:

https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/
