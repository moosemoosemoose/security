# Stegasaurus (Encrypted Image Steganography)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y31R5FVX)

Stegasaurus is a Python steganography tool that hides and retrieves encrypted messages inside images using least‑significant‑bit (LSB) encoding. Messages are encrypted with a password before being embedded, providing confidentiality in addition to concealment.

The project focuses on understanding how steganography works at the bit level, how encryption can be layered on top of hidden data, and how image capacity limits affect embedded payloads.

**Features**

* LSB‑based steganography (RGB channels)
* Password‑based encryption using PBKDF2 + Fernet
* Random salt generation for key derivation
* 32‑bit length header for reliable message extraction
* Read (r) and write (w) modes via command‑line interface
* Automatic capacity checking to prevent image overflow

**Technologies Used**

* Python 3
* Pillow (PIL)
* cryptography (PBKDF2HMAC, Fernet)
* argparse
* Base64 encoding

**Purpose**

This project was built to learn:

* How LSB steganography works at the bit level
* Secure key derivation from passwords
* Combining encryption with data hiding
* Image data traversal and manipulation
* Tradeoffs between payload size and image dimensions

⚠️ Educational use only. This implementation prioritizes clarity and learning over stealth, robustness, or resistance to steganalysis.
