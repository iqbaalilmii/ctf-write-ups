Writeup: ICMP Steganography & Zlib Reassembly

Category: Digital Forensics / Network 

Difficulty: Hard

The challenge provided a network capture file (PCAP) containing a lot of ICMP (Ping) traffic. 
When looking at the Data Payload of each packet, I noticed a weird Hex string. All the data started with 78 9c. In forensics, these are the "Magic Bytes" for Zlib Compression.
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/718a576b-815a-4d6f-963c-daa96acb094b" />

And after I dumped each of the icmp packets, I got a zlib files, and I uncompress it all it gives me a png that contains each flag character.
The problem is, if I dumped the data directly, the order was completely random, I tried by sorting it using time on Wireshark, but it still gives a random order.
After digging deeper into the hex, I noticed a secret pattern. Every payload had one extra byte (2 hex digits) at the very end. 
The Hypothesis is, this last byte is an Index (Sequence Number). The sender sent the data out of order to confuse us. I needed to sort them before decompressing. Since there were too many packets, doing it manually would take forever so i ask AI to wrote me a python script to sorting and decompressing process, I named this script solver.py.
After running the script, a folder named extracted_frames appeared. It contained many PNG files. Each file showed one single character. By looking at the images in order (frame_000.png, frame_001.png, etc.), the flag finally appeared!.

Flag: {easy_pcap_for_us_all_00efd3a4cc}

What I learned from this chall?
ICMP (Ping) is supposed to be for testing networks, but it has a "Data" field that can be used to sneak out secrets. This is a real-world technique called ICMP Tunneling. In networking, packets often arrive "out of order," and we must use indices to rebuild them. And last, python is the key, being able to code is a superpower in CTF forensics. It turns a "stuck" situation into a "solved" one. Doing this manually for 30+ packets would take forever and lead to mistakes. Python is a "must-have" skill for any forensics challenge to handle repetitive tasks quickly.
