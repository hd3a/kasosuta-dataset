import streamlit as st
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


st.title("rsa鍵")


# =========================
# 鍵生成
# =========================
st.header("🔐 新規鍵生成")

if st.button("鍵を生成"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    # ===== PEM =====
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # ===== DER → Base64 (短縮) =====
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    short_private = base64.b64encode(private_der).decode()
    short_public = base64.b64encode(public_der).decode()

    st.subheader("🗝 秘密鍵 (PEM)")
    st.text_area("Private PEM", private_pem.decode(), height=200)

    st.subheader("🔓 公開鍵 (PEM)")
    st.text_area("Public PEM", public_pem.decode(), height=150)

    st.subheader("⚡ 短い秘密鍵")
    st.text_area("Short Private (Base64)", short_private, height=150)

    st.subheader("⚡ 短い公開鍵")
    st.text_area("Short Public (Base64)", short_public, height=100)


# =========================
# 短い秘密鍵から復元
# =========================
st.header("📂 短い秘密鍵から復元")

short_input = st.text_area("短い秘密鍵(Base64)を貼れ", height=150)

if st.button("復元"):
    try:
        private_der = base64.b64decode(short_input)
        private_key = serialization.load_der_private_key(
            private_der,
            password=None,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        st.success("復元成功")
        st.text_area("復元された公開鍵", public_pem.decode(), height=150)

    except Exception as e:
        st.error("復元失敗")
        st.code(str(e))
