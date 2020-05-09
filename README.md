# arp-spoof-detector
ARP Spoof Detector is a network security tool written in python3 for the Linux system. The tool examines all the incoming ARP response packet and identifies whether the response packet is a spoofed packet or not. If an ARP spoof attack detects it notifies the user with the attacker mac address and the total count of spoof packet the system receives

USAGE: 

git clone  

cd arp-spoof-detector 

sudo python3 installer.py  

sudo python3 arp-spoof-detector.py -i [ interface_name ]
