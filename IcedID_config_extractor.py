import pefile
import argparse
from Crypto.Cipher import ARC4

def get_data(pe_file):
    for section in pe_file.sections:
        if b".data" in section.Name:
            return section.get_data()
    return None

def extract_utils(data):
    if data is None:
        raise ValueError("Error in the .data section.")
    key = data[:8]
    encrypted_part = data[8:]
    return key, encrypted_part

def rc4_decrypt(key, data_enc):
    cipher = ARC4.new(key)
    return cipher.decrypt(data_enc)

def extract_c2s(decrypted_data):
    try:
        decoded = decrypted_data.decode("utf-8", errors="ignore")
        parts = decoded.split('\x00')
        c2s = [p for p in parts if "." in p and len(p) > 4] 
        return c2s
    except Exception as e:
        print(f"[!] Error in the configuration extraction : {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        prog='extract_conf.py',
        description='Extract RC4 key, crypted data and display the configuration.')
    parser.add_argument("filepath", help="PE filepath (IceID)")
    args = parser.parse_args()

    print(f"[+] PE file : {args.filepath}")
    pe = pefile.PE(args.filepath)

    data_section = get_data(pe)
    key, encrypted = extract_utils(data_section)
    decrypted = rc4_decrypt(key, encrypted)

    print(f"[+] RC4 Key: {key.hex()}")
    c2s = extract_c2s(decrypted)

    if c2s:
        print("[+] Configuration :")
        for c2 in c2s:
            print(f"    - {c2}")
    else:
        print("[!]")

if __name__ == "__main__":
    main()
