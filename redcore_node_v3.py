
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import rsa

app = Flask(__name__)
CORS(app)

if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
    (pubkey, privkey) = rsa.newkeys(2048)
    with open('private_key.pem', 'wb') as p:
        p.write(privkey.save_pkcs1('PEM'))
    with open('public_key.pem', 'wb') as p:
        p.write(pubkey.save_pkcs1('PEM'))
else:
    with open('private_key.pem', 'rb') as p:
        privkey = rsa.PrivateKey.load_pkcs1(p.read())
    with open('public_key.pem', 'rb') as p:
        pubkey = rsa.PublicKey.load_pkcs1(p.read())

@app.route('/')
def home():
    return "Red Core Node v3 Online and Secure"

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    recipient_url = data.get('recipient_url')
    recipient_pubkey_str = data.get('recipient_public_key')
    message = data.get('message')
    
    if recipient_url and recipient_pubkey_str and message:
        recipient_pubkey = rsa.PublicKey.load_pkcs1(recipient_pubkey_str.encode())
        encrypted_message = rsa.encrypt(message.encode(), recipient_pubkey)
        signature = rsa.sign(encrypted_message, privkey, 'SHA-256')
        
        return jsonify({
            "encrypted_message": encrypted_message.hex(),
            "signature": signature.hex(),
            "sender_url": data.get('sender_url')
        })
    return jsonify({"status": "Missing fields."}), 400

@app.route('/public_key.pem', methods=['GET'])
def get_public_key():
    with open('public_key.pem', 'r') as f:
        pubkey = f.read()
    return pubkey, 200, {'Content-Type': 'text/plain'}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
