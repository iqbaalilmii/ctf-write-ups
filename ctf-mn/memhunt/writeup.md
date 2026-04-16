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

