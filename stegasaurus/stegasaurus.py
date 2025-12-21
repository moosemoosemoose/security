'''STEGASAURUS
Steganography tool for reading/writing encrypted messages in an image'''
import argparse
import sys
import os
import base64
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from PIL import Image
# ------------------- Crypto helpers -------------------

def derive_key(password: str, salt: bytes):
    """
    Derive a 32-byte key from a password and salt using PBKDF2 HMAC SHA256.
    Fernet requires a 32-byte base64-encoded key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_message(msg_bytes: bytes, password: str):
    """
    Encrypts the message bytes with a password.
    Prepends a 16-byte random salt to the ciphertext.
    """
    salt = os.urandom(16)                  # Random salt for key derivation
    key = derive_key(password, salt)       # Derive encryption key from password + salt
    f = Fernet(key)
    ciphertext = f.encrypt(msg_bytes)
    return salt + ciphertext               # Store salt with ciphertext for decryption

def decrypt_message(data: bytes, password: str):
    """
    Decrypts a message encrypted with encrypt_message.
    Extracts the salt from the first 16 bytes to derive the key.
    """
    salt = data[:16]
    ciphertext = data[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(ciphertext)

# ------------------- Bit helpers -------------------

def int_to_bits(value, bit_count):
    """
    Convert an integer to a list of bits (MSB first).
    Used for the 32-bit length header.
    """
    return [(value >> i) & 1 for i in reversed(range(bit_count))]

def bytes_to_bits(data):
    """
    Convert a sequence of bytes into a flat list of bits (MSB first).
    Each byte becomes 8 bits.
    """
    bits = []
    for byte in data:
        bits.extend(int_to_bits(byte, 8))
    return bits

def bits_to_bytes(bits):
    """
    Convert a list of bits back into bytes.
    Groups every 8 bits into one byte.
    """
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b         # Shift left and add current bit
        out.append(byte)
    return bytes(out)

def prepare_message_bits(message, password):
    '''Prepping bits'''
    msg_bytes = encrypt_message(message.encode("utf-8"), password)
    msg_len = len(msg_bytes)
    header_bits = int_to_bits(msg_len, 32)
    msg_bits = bytes_to_bits(msg_bytes)
    return header_bits + msg_bits

def embed_bits_into_image(im_name, all_bits):
    '''Embedding bits (Too much was being done in one scope)'''
    pixels = im_name.load()
    width, height = im_name.size
    bit_idx = 0

    for y in range(height):
        for x in range(width):
            if bit_idx >= len(all_bits):
                return im_name
            r, g, b = pixels[x, y]
            channels = [r, g, b]
            for i in range(3):
                if bit_idx < len(all_bits):
                    channels[i] = (channels[i] & ~1) | all_bits[bit_idx]
                    bit_idx += 1
            pixels[x, y] = tuple(channels)

    return im_name

# ------------------- LSB helpers -------------------

def max_capacity_bits(im_name):
    """
    Calculate maximum number of bits that can be stored in an image.
    3 bits per pixel (RGB), ignoring alpha.
    """
    width, height = im_name.size
    return width * height * 3

def extract_lsb(im_name, max_bits=None):
    """
    Extract the least significant bit of each RGB channel from the image.
    Stops if max_bits is reached (useful for reading length header or message only).
    Returns a flat list of bits.
    """
    width, height = im_name.size
    pixels = im_name.load()
    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            for channel in (r, g, b):
                bits.append(channel & 1)          # Extract LSB
                if max_bits and len(bits) >= max_bits:
                    return bits
    return bits

# ------------------- Encoder / Writer -------------------

def msg_encoder(im_name, message, password):
    '''
    Encrypts the message with a password and embeds it into the image's LSBs.
    Returns a modified image.
    '''
    im_name = im_name.copy().convert("RGB")
    all_bits = prepare_message_bits(message, password)

    if len(all_bits) > max_capacity_bits(im_name):
        raise ValueError("Message too large for this image")

    return embed_bits_into_image(im_name, all_bits)

# ------------------- Reader / Decoder -------------------

def read_message(im_name, password):
    """
    Extracts and decrypts a hidden message from the image.
    Returns decoded string or error message if decryption fails.
    """
    # Step 1: extract 32-bit length header
    header_bits = extract_lsb(im_name, 32)
    msg_len = int(''.join(str(b) for b in header_bits), 2)  # Convert bits to int

    # Step 2: extract message bits based on length
    all_bits = extract_lsb(im_name, 32 + msg_len * 8)
    msg_bits = all_bits[32:]                               # Skip header bits
    msg_bytes = bits_to_bytes(msg_bits)                    # Convert bits to bytes

    # Step 3: decrypt with password
    try:
        decrypted = decrypt_message(msg_bytes, password)
        return decrypted.decode("utf-8")
    except (AttributeError, ValueError, KeyError, OSError):
        return "[!] Incorrect password or corrupted data"

# ------------------- CLI -------------------

def parse_args():
    '''This is here to please pylint'''
    parser = argparse.ArgumentParser(description="LSB Steganography with password")
    parser.add_argument("filename", help="Image file to read/write")
    parser.add_argument("-m", "--mode", choices=["r", "w"], default="r",
                        help="Mode: r=read, w=write")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if not args.filename:
        print("Error: No filename provided")
        sys.exit(1)

    with Image.open(args.filename) as im:
        im = im.convert("RGB")

        if args.mode == "r":
            passwd = input("Enter password: ")
            msg = read_message(im, passwd)
            print("Hidden message:", msg)
            time.sleep(5)

        elif args.mode == "w":
            msg = input("Enter message to encode: ")
            passwd = input("Enter password: ")
            im = msg_encoder(im, msg, passwd)
            OUT_FILE = "encoded.png"
            im.save(OUT_FILE)
            print(f"Message encoded to {OUT_FILE}")
