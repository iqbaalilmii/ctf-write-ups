# Memory

Category : Forensics

`aku ninggalin gambar flagnya di Desktop, tapi tiba tiba hilang... kamu bisa ga bantu aku recover flagnya?`

attachment : `https://drive.google.com/file/d/1DHEQLPOXdJzidis-2cwe9UUw0mb327ZO/view`

Deskripsinya bilang hint yang penting, "Desktop", dengan ini, kita tahu bahwa path gambar flagnya ada di Desktop, jadii kita mau pake plugin mftparser dan filescan dari volatility

<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/89f59719-0a03-4679-b310-2d5ae896ba7e" />
Pertama-tama, aku mau kenal sama sistem memory dump ini dulu, tapi ini file dump yang diambil dari ftk imager, jadii raw, kita harus pake plugin windows.info dari volatility3 buat ngecheck profilenya

dari output plugin `windows.info`, bisa disimpulkan, ini file di dump dari Windows 10, buildnya 19041, dan 64 bit, jadi, profile untuk volatility2 yang cocok adalah `Win10x64_19041`
