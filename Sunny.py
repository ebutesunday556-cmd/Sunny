
import base64
import hmac
import os

from flask import Flask, request, render_template_string
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

app = Flask(__name__)

APP_NAME = "SUNNY SECURE CIPHER TOOL"
PBKDF2_ITERATIONS = 600000
SALT_LENGTH = 16
IV_LENGTH = 16
MAC_LENGTH = 32


def derive_keys(passcode, salt):
    """Derive separate AES and HMAC keys."""
    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    ).derive(passcode.encode("utf-8"))

    return derived[:32], derived[32:]


def encrypt_message(message, passcode):
    """Encrypt text using AES-256-CBC and authenticate with HMAC."""
    if len(passcode) < 8:
        raise ValueError(
            "Passcode must contain at least 8 characters."
        )

    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)

    encryption_key, mac_key = derive_keys(passcode, salt)

    # AES-CBC requires PKCS7 padding.
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode("utf-8"))
    padded += padder.finalize()

    encryptor = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv)
    ).encryptor()

    encrypted = encryptor.update(padded) + encryptor.finalize()

    header = b"VSM1" + salt + iv + encrypted
    mac = hmac.new(mac_key, header, digestmod="sha256").digest()

    return base64.b64encode(header + mac).decode("ascii")


def decrypt_message(encoded, passcode):
    """Verify HMAC, then decrypt the VSM1 ciphertext."""
    if not passcode:
        raise ValueError("Passcode is required.")

    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("Invalid ciphertext.") from None

    if len(raw) < 84 or raw[:4] != b"VSM1":
        raise ValueError("Invalid ciphertext.")

    salt = raw[4:20]
    iv = raw[20:36]
    encrypted = raw[36:-MAC_LENGTH]
    received_mac = raw[-MAC_LENGTH:]

    if not encrypted or len(encrypted) % 16 != 0:
        raise ValueError("Invalid ciphertext.")

    encryption_key, mac_key = derive_keys(passcode, salt)

    authenticated_data = raw[:-MAC_LENGTH]
    expected_mac = hmac.new(
        mac_key,
        authenticated_data,
        digestmod="sha256"
    ).digest()

    # Authenticate before decrypting.
    if not hmac.compare_digest(expected_mac, received_mac):
        raise ValueError("Decryption failed.")

    decryptor = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv)
    ).decryptor()

    padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode("utf-8")


HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SUNNY Secure Cipher Tool</title>
<style>
* { box-sizing: border-box; }

body {
    font-family: Arial, sans-serif;
    background: #f0f4f8;
    padding: 20px;
    max-width: 650px;
    margin: auto;
    color: #222;
}

h2 { text-align: center; color: #123456; }

.subtitle {
    text-align: center;
    margin-bottom: 25px;
}

.card {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 8px #0002;
    margin-bottom: 20px;
}

input, textarea {
    display: block;
    width: 100%;
    padding: 12px;
    margin: 8px 0 15px;
    border: 1px solid #ccc;
    border-radius: 5px;
    font-size: 15px;
    font-family: inherit;
}

textarea { resize: vertical; }

button {
    background: #0759b5;
    color: white;
    padding: 12px 18px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    width: 100%;
    font-size: 16px;
}

button:hover { background: #06458b; }

.result {
    background: #e8f0f7;
    padding: 12px;
    border-radius: 5px;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
    line-height: 1.5;
}

.error { color: #b00020; }

.note {
    font-size: 13px;
    color: #555;
    line-height: 1.6;
}

label {
    font-weight: bold;
    font-size: 14px;
}
</style>
</head>
<body>

<h2>SUNNY SECURE CIPHER TOOL</h2>
<p class="subtitle">
Encrypt and decrypt messages using a passcode.
</p>

<div class="card">
<h3>Encrypt Message</h3>
<form method="POST" action="/encrypt-web">
<input type="hidden" name="action" value="encrypt">

<label for="message">Enter your message:</label>
<textarea id="message" name="message" rows="4"
required>{{ enc_msg }}</textarea>

<label for="enc-passcode">Create a passcode:</label>
<input id="enc-passcode" type="password" name="passcode"
minlength="8" required autocomplete="new-password">

<button type="submit">Encrypt Message</button>
</form>

{% if enc_result %}
<h4>Encryption Result</h4>
<div class="result {% if error_action == 'encrypt' %}error{% endif %}"
role="status">{{ enc_result }}</div>
{% endif %}
</div>

<div class="card">
<h3>Decrypt Message</h3>
<form method="POST" action="/decrypt-web">
<input type="hidden" name="action" value="decrypt">

<label for="ciphertext">Enter ciphertext:</label>
<textarea id="ciphertext" name="ciphertext" rows="4"
required>{{ dec_cipher }}</textarea>

<label for="dec-passcode">Enter the same passcode:</label>
<input id="dec-passcode" type="password" name="passcode"
required autocomplete="current-password">

<button type="submit">Decrypt Message</button>
</form>

{% if dec_result %}
<h4>Decryption Result</h4>
<div class="result {% if error_action == 'decrypt' %}error{% endif %}"
role="status">{{ dec_result }}</div>
{% endif %}
</div>

<p class="note">
Keep your passcode safe. This tool uses AES-256-CBC with
HMAC-SHA256 authentication. The same passcode is required
to decrypt the message.
</p>

</body>
</html>
"""


def render_page(
    enc_msg="",
    enc_result="",
    dec_cipher="",
    dec_result="",
    error_action=""
):
    return render_template_string(
        HTML,
        enc_msg=enc_msg,
        enc_result=enc_result,
        dec_cipher=dec_cipher,
        dec_result=dec_result,
        error_action=error_action
    )


@app.route("/", methods=["GET"])
def home():
    return render_page()


@app.route("/encrypt-web", methods=["POST"])
def encrypt_web():
    message = request.form.get("message", "")
    passcode = request.form.get("passcode", "")

    try:
        if not message:
            raise ValueError("Enter a message to encrypt.")

        result = encrypt_message(message, passcode)

        return render_page(
            enc_msg=message,
            enc_result=result
        )

    except (ValueError, UnicodeError):
        return render_page(
            enc_msg=message,
            enc_result=(
                "Encryption failed. Enter a message and a "
                "passcode of at least 8 characters."
            ),
            error_action="encrypt"
        ), 400


@app.route("/decrypt-web", methods=["POST"])
def decrypt_web():
    ciphertext = request.form.get("ciphertext", "").strip()
    passcode = request.form.get("passcode", "")

    try:
        if not ciphertext:
            raise ValueError("Enter ciphertext to decrypt.")

        original = decrypt_message(ciphertext, passcode)

        return render_page(
            dec_cipher=ciphertext,
            dec_result=original
        )

    except (ValueError, UnicodeError):
        return render_page(
            dec_cipher=ciphertext,
            dec_result=(
                "Decryption failed. Check your ciphertext "
                "and passcode."
            ),
            error_action="decrypt"
        ), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
