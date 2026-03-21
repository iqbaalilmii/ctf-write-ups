Writeup: ICMP Steganography & Zlib Reassembly

Category: Digital Forensics / Network 

Difficulty: Hard

The challenge provided a network capture file (PCAP) containing a lot of ICMP (Ping) traffic. 
When looking at the Data Payload of each packet, I noticed a weird Hex string. All the data started with 78 9c. In forensics, these are the "Magic Bytes" for Zlib Compression.
<img width="699" height="410" alt="image" src="https://github.com/user-attachments/assets/f4600571-9fc2-4ac1-83b4-5cdf54598d73" />
