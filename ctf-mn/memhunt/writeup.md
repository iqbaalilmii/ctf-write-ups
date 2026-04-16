# Write-up: Haruul Zangi Memory Forensics Challenge

Challenge Information
Target: Linux Memory Dump (memhunt.mem)

Category: Memory Forensics & Cryptography

Difficulty: Hard

Pertama, aku coba pake plugin windows.info, tapi gabisa, dan aku coba pake plugin banners.Banners buat nentuin kernel linux yang spesifik karna volatility butuh symbol table buat baca struktur data di memory.
```
vol3 -f memhunt.mem banners.Banners
```
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/e72c55d3-c8f2-4033-8d8b-5c8a465f35bc" />
ternyata, ini pake Linux version 4.15.0-213-generic, aku langsung aja cari file .ddeb yang sesuai di repositori Ubuntu (seperti linux-image-unsigned-4.15.0-213-generic-dbgsym). Menggunakan tool dwarf2json untuk mengubah file vmlinux dari paket debug tersebut menjadi file .json

Setelah simbol terpasang, aku langsung cek bash history pake `linux.bash.Bash`.
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/5fa24b2b-7524-4d91-ac64-d56055719e67" />
terlihat user menginstall LiMe (Linux Memory Extractor) untuk ngambil dump memori, dia juga coba menghapus jejak dengan perintah rm ~/.bash_history dan cat /dev/null > ~/.bash_history.

setelah itu, aku check proses list yang lagi jalan pake plugin `linux.pslist`
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/f4a10af7-4b65-4ae4-aa73-4619528fd13e" />

dan nemuin prosess java yang mencurigakan, kenapa? karna UIDnya 0 yang berarti yang ngejalanin root, disini karna proses java itu mencurigakan banget, aku langsung aja dump pake plugin `linux.pagecache.RecoverFs`
<img width="1405" height="818" alt="image" src="https://github.com/user-attachments/assets/ccec4627-e424-4cbe-b98d-65797aa05f0d" />

file tar.gznya di decompress dengan `tar -xzvf recovered_fs.tar.gz`, dan aku langsung aja find file java mencurigakan tadi, dan menemukan path `./extracted_files/262cd342-5473-4dde-8b29-fff35b4a0bb8/home/zangi/zan/needed.java`

langsung aja di cat dan nemuin script java ini
<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/143406a1-6da8-44bb-8479-2687b94afb7c" />

langsung aja wok, decrypt pake tools online CyberChef

<img width="1919" height="956" alt="image" src="https://github.com/user-attachments/assets/f514c26a-bcd8-4bff-ab0c-65eb5d178136" />

```
HZ2023{MNSEC_HARUULZANGI_Q1RGLSJOHqlTRr76RnWTl4lJW1juYR1b}
```
