"""
day2_test_rsa_keygen.py
 Sinh cặp khóa RSA, lưu ra file, đọc lại để kiểm tra.
 
"""
 
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
 
from crypto.rsa_utils import generate_rsa_keypair, save_key_to_file, load_key_from_file
 
KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")
 
def main():
    print("=" * 60)
    print("NGÀY 2 - TEST SINH KHÓA RSA")
    print("=" * 60)
 
    print("\n[1] Đang sinh cặp khóa RSA 2048-bit...")
    private_key, public_key = generate_rsa_keypair()
    print("    -> Sinh khóa thành công.")
    print(f"    -> Kích thước khóa (bit): {private_key.size_in_bits()}")
 
    os.makedirs(KEYS_DIR, exist_ok=True)
    priv_path = os.path.join(KEYS_DIR, "peerB_private.pem")
    pub_path = os.path.join(KEYS_DIR, "peerB_public.pem")
 
    print(f"\n[2] Đang lưu khóa ra file...")
    save_key_to_file(private_key, priv_path)
    save_key_to_file(public_key, pub_path)
    print(f"    -> Private key: {priv_path}")
    print(f"    -> Public key : {pub_path}")
 
    print(f"\n[3] Đang đọc lại khóa từ file để kiểm tra...")
    loaded_private = load_key_from_file(priv_path)
    loaded_public = load_key_from_file(pub_path)
 
    assert loaded_private.export_key() == private_key.export_key()
    assert loaded_public.export_key() == public_key.export_key()
    print("    -> Đọc lại khớp 100% với khóa gốc. OK.")
 
    print("\n[4] Nội dung file public key (để chèn ảnh chụp màn hình vào báo cáo):")
    print("-" * 60)
    with open(pub_path, "r") as f:
        print(f.read())
    print("-" * 60)
 
    print("KẾT QUẢ NGÀY 2: THÀNH CÔNG")
    print("=" * 60)
 
 
if __name__ == "__main__":
    main()
