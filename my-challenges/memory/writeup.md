# Memory

Category : Forensics

`aku ninggalin gambar flagnya di Desktop, tapi tiba tiba hilang... kamu bisa ga bantu aku recover flagnya?`

attachment : 
```
https://drive.google.com/file/d/1DHEQLPOXdJzidis-2cwe9UUw0mb327ZO/view
```
Deskripsinya bilang hint yang penting, "Desktop", dengan ini, kita tahu bahwa path gambar flagnya ada di Desktop, jadii kita mau pake plugin mftparser dan filescan dari volatility

<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/89f59719-0a03-4679-b310-2d5ae896ba7e" />
Pertama-tama, aku mau kenal sama sistem memory dump ini dulu, aku pake plugin windows.info dari volatility3 buat ngecheck profilenya

dari output plugin `windows.info`, bisa disimpulkan, ini file di dump dari Windows 10, buildnya 19041, dan 64 bit, jadi, profile untuk volatility2 yang cocok adalah `Win10x64_19041`

<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/7060cc63-7844-480a-aae1-ad268f46fccf" />
Disini aku langsung aja pake plugin  `windows.filescan` dari volatility3 dan grep "desktop" tapi sayangnya ga dapet apa apa

<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/1933cda5-fd21-4d57-ac61-cb0512ca9832" />

```
vol2 -f memdump.mem --profile=Win10x64_19041 mftparser | grep -i "desktop"
```
tapi, pas aku coba pake plugin mftparser dari volatility2, aku nemu `flag.enc`

aku udah coba dump flag.enc itu pake plugin dumpfiles, tapi plugin filescan ga nemu file itu di memory dumpnya

<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/2b3d4c78-2207-42b6-9ede-80e5a884b96b" />

disini aku langsung aja pake tool findnya HxD search all "flag.enc" dan nemu script Powershell ini

```
$ifPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'flag.png')
$efPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'flag.enc')

$aes = New-Object System.Security.Cryptography.AesManaged
$aes.KeySize = 256
$aes.BlockSize = 128
$aes.GenerateKey()
$aes.GenerateIV()

$cee = [System.Convert]::ToBase64String($aes.Key)
$vee = [System.Convert]::ToBase64String($aes.IV)

$content = [System.IO.File]::ReadAllBytes($ifPath)

$encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)
$encryptedData = $encryptor.TransformFinalBlock($content, 0, $content.Length)

$encryptedBase64 = [System.Convert]::ToBase64String($encryptedData)

[System.IO.File]::WriteAllText($efPath, $encryptedBase64)

[System.Environment]::SetEnvironmentVariable("ENCD", $encryptedBase64, [System.EnvironmentVariableTarget]::User)
[System.Environment]::SetEnvironmentVariable("ENCK", $cee, [System.EnvironmentVariableTarget]::User)
[System.Environment]::SetEnvironmentVariable("ENCV", $vee, [System.EnvironmentVariableTarget]::User)

if (Test-Path $ifPath) {
    Remove-Item $ifPath -Force
}
```

ternyata, si attacker ngeenkripsi flag.png nya pake AES, dia juga naro key, IV, dan data gambarnya di Environment Variable

<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/ac977386-2075-407b-bcf9-bb3084e02723" />


disini aku langsung aja pake plugin windows.envars volatility3 buat check env variablesnya


dan outputnya langsung keliatan image data, key, dan ivnya dalam bentuk base64


<img width="1913" height="988" alt="image" src="https://github.com/user-attachments/assets/9ed7ca58-3f1f-4bea-bc5d-a73eb0a34590" />


langsung aja taro di cyberchef, dan mendapatkan gambar flag ini


<img width="1115" height="272" alt="image" src="https://github.com/user-attachments/assets/5e6e2391-0920-42d0-be3c-bcaa69af7b4d" />


`FGTE{follin4_m3mOry_dump3r_succ3ss_c0ngr4ts}`
