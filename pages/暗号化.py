import streamlit as st
import base64
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

st.title("暗号化")

# =========================
# 鍵生成
# =========================
st.header("① 鍵生成")

if st.button("鍵生成"):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    st.session_state.private_key = base64.b64encode(private_der).decode()
    st.session_state.public_key = base64.b64encode(public_der).decode()

# 表示
if "private_key" in st.session_state:
    st.text_area("短い秘密鍵", st.session_state.private_key, height=100)
    st.text_area("短い公開鍵", st.session_state.public_key, height=80)

# =========================
# 暗号化
# =========================
st.header("② 暗号化")

my_private_input = st.text_area("自分の秘密鍵(Base64)")
peer_public_input = st.text_area("相手の公開鍵(Base64)")
plaintext = st.text_input("暗号化する文字")

if st.button("暗号化"):
    try:
        private_key = serialization.load_der_private_key(
            base64.b64decode(my_private_input),
            password=None,
            backend=default_backend()
        )

        peer_public_key = serialization.load_der_public_key(
            base64.b64decode(peer_public_input),
            backend=default_backend()
        )

        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"chat",
        ).derive(shared_key)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

        result = base64.b64encode(iv + ciphertext).decode()
        st.success("暗号文")
        st.text_area("Cipher", result)

    except Exception as e:
        st.error("暗号化失敗")
        st.code(str(e))


# =========================
# 復号
# =========================
st.header("③ 復号")

cipher_input = st.text_area("暗号文(Base64)")

if st.button("復号"):
    try:
        private_key = serialization.load_der_private_key(
            base64.b64decode(my_private_input),
            password=None,
            backend=default_backend()
        )

        peer_public_key = serialization.load_der_public_key(
            base64.b64decode(peer_public_input),
            backend=default_backend()
        )

        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"chat",
        ).derive(shared_key)

        raw = base64.b64decode(cipher_input)
        iv = raw[:16]
        ciphertext = raw[16:]

        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        st.success("復号結果: " + decrypted.decode())

    except Exception as e:
        st.error("復号失敗")
        st.code(str(e))
