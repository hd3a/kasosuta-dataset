import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

st.title("楕円曲線暗号 ECDH + AES デモ")

# --- 鍵生成 ---
if st.button("鍵ペア生成"):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    st.session_state.private_key = private_key
    st.session_state.public_key = public_key

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    st.text_area("公開鍵（相手に渡す）", pub_bytes.decode(), height=200)

# --- 相手公開鍵入力 ---
peer_pub_input = st.text_area("相手の公開鍵を貼って")

# --- 暗号化 ---
plaintext = st.text_input("暗号化するテキスト")

if st.button("暗号化"):
    if "private_key" not in st.session_state:
        st.error("先に鍵ペア生成して")
    else:
        peer_public_key = serialization.load_pem_public_key(
            peer_pub_input.encode(),
            backend=default_backend()
        )

        shared_key = st.session_state.private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

        result = base64.b64encode(iv + ciphertext).decode()
        st.text_area("暗号文", result)

# --- 復号 ---
cipher_input = st.text_area("復号する暗号文")

if st.button("復号"):
    if "private_key" not in st.session_state:
        st.error("先に鍵ペア生成して")
    else:
        peer_public_key = serialization.load_pem_public_key(
            peer_pub_input.encode(),
            backend=default_backend()
        )

        shared_key = st.session_state.private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)

        raw = base64.b64decode(cipher_input)
        iv = raw[:16]
        ciphertext = raw[16:]

        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        st.success("復号結果: " + decrypted.decode())
