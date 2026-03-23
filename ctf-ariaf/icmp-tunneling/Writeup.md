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
```
import zlib
import binascii
import os

# Create a folder for the results
os.makedirs('extracted_frames', exist_ok=True)

def solve():
    # 'icmp.txt' contains the hex payloads from Wireshark
    with open('icmp.txt', 'r') as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]

    # Step 1: Extract and Index
    indexed_data = []
    for line in lines:
        try:
            raw_bytes = binascii.unhexlify(line)
            
            # The last byte is the index
            index = raw_bytes[-1] 
            
            # The rest is the Zlib payload
            zlib_payload = raw_bytes[:-1]
            
            indexed_data.append((index, zlib_payload))
        except:
            continue

    # Step 2: Sort based on the index (0, 1, 2...)
    indexed_data.sort(key=lambda x: x[0])

    # Step 3: Decompress and Save
    for idx, data in indexed_data:
        try:
            # Each packet is actually one small PNG image
            image_content = zlib.decompress(data)
            
            filename = f'extracted_frames/frame_{idx:03d}.png'
            with open(filename, 'wb') as f_out:
                f_out.write(image_content)
            print(f"[+] Extracted index {idx}")
        except Exception as e:
            print(f"[-] Error at index {idx}: {e}")

if __name__ == "__main__":
    solve()
```
After running the script, a folder named extracted_frames appeared. It contained many PNG files. Each file showed one single character. By looking at the images in order (frame_000.png, frame_001.png, etc.), the flag finally appeared!.

<img width="1889" height="986" alt="image" src="https://github.com/user-attachments/assets/2dd4db15-ae30-459d-9099-ba7326c6cf57" />

Flag: {easy_pcap_for_us_all_00efd3a4cc}

What I learned from this chall?
ICMP (Ping) is supposed to be for testing networks, but it has a "Data" field that can be used to sneak out secrets. This is a real-world technique called ICMP Tunneling. In networking, packets often arrive "out of order," and we must use indices to rebuild them. And last, python is the key, being able to code is a superpower in CTF forensics. It turns a "stuck" situation into a "solved" one. Doing this manually for 30+ packets would take forever and lead to mistakes. Python is a "must-have" skill for any forensics challenge to handle repetitive tasks quickly.
