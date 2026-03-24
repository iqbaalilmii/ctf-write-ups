# *JWT Forensic & Web Exploration (Hard)*

Name: Euphonium Dashboard

Category: Web / OSINT

Difficulty: Hard

Target: https://euphonium-fgte.vercel.app

**1. Initial Recon (OSINT)**

The challenge provided a dashboard and an image of Kumiko Oumae (the protagonist of Hibike! Euphonium). The hint mentioned that the secret key involves "Personal info + Hobbies" of the character.

I did some quick OSINT on the character:

* Character Name: Kumiko Oumae

* School: Kitauji High School

* Instrument (Hobby): Euphonium

* Favorite Item: Cactus (Euphorbia obesa) / Tubi-kun

**2. JWT Analysis**

When I logged in, the web gave me a session cookie named token. I decoded it on jwt.io and found the payload:

```
{
  "sub": "manaflagwoyyyy",
  "role": "user"
}
```
<img width="1919" height="1066" alt="image" src="https://github.com/user-attachments/assets/caad180b-1b6d-4783-a4bc-970ae2f99769" />

The algorithm used was `HS256`, which means I needed a secret key to sign a new token with the "role": "admin" privilege.

**3. Cracking the Secret (Brute Force)**

Since the hint telling me that you need to a custom wordlist, i knew the secret was related to Kumiko's hobbies, I created a custom Python script to generate a massive wordlist. I combined keywords like `Kumiko`, `Euphonium`, `Music`, and `Kitauji`.

I used Hashcat (v7.1.2) on my Linux environment (WSL).
```
hashcat -m 16500 target.txt wordlist.txt -r /usr/share/hashcat/rules/T0XlC.rule
```
After a few seconds and millions of attempts, Hashcat successfully cracked the secret!

<img width="1920" height="1128" alt="image" src="https://github.com/user-attachments/assets/6d2025da-675f-4e66-8679-0764a6360ddc" />
Secret Key: `euphonium@!`

The secret key was not in the raw wordlist. I used the `T0XlC.rule` to perform a hybrid attack, which dynamically appended special characters and symbols to the base words. This allowed Hashcat to discover the correct secret: `euphonium@!`.

**4. Privilege Escalation**

I went back to jwt.io and performed the following steps:

Pasted the original token.

Modified the payload from `"role": "user"` to `"role": "admin"`.

Entered the secret key `euphonium@!` in the signature box.

Copied the new Admin Token.

**5. Final Injection**

I tried using the Console, but the token was protected. So I switched to the Application tab for a manual override:

I completely deleted the existing token cookie to clear any session restrictions.

* Manual Crafting: I created a brand new cookie entry.

* Name: token

Value: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtYW5hZmxhZ3dveXl5eXkiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NzQzNTI1MTksImV4cCI6MTc3NDM1NjExOX0.BOfYCqMfyaVS4KoMFpRLOo2FRptCn1dj5bEcJ8C5K30`

* I ensured the path was set to / and then hit Enter.

* The Dashboard changed, and the flag appeared!
<img width="1919" height="1060" alt="image" src="https://github.com/user-attachments/assets/39416e09-4024-4fa5-8fcc-1b5cce6627d8" />

Flag : `FGTE{Jwt_3uph0n1um_Kum1k0_4ever}`

**Lessons Learned**

* Don't Underestimate "Weak" Secrets: Even if a secret key looks unique (like a character's hobby), if it’s based on public info (OSINT), it’s not safe. A hacker with a good wordlist and a powerful laptop can crack it in seconds.

* The Power of Hashcat Rules: I learned that a raw wordlist isn't enough. Using rules like T0XlC.rule is a game changer because it tries variations (like adding @!) that aren't in the original file. Brute force is all about patterns, not just guessing words.

* JWT is Not Encryption, It’s Signing: This challenge taught me that JWT tokens aren't "hidden" data. Anyone can decode them. The only thing protecting them is the Signature. If you get the secret key, you own the whole system.

* Client-Side Security is Tricky: I learned how to bypass browser restrictions. Even if the console says undefined or blocks your script, you can still manually manipulate cookies in the Application tab. Knowing how to delete and re-create cookies is a must-have skill for web exploitation.

* Persistence is Key: In CTF, things rarely work on the first try. I had to pivot from the console to manual cookie injection and keep checking the payload until it worked. "Try harder" is real!
