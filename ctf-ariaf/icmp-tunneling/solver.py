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
