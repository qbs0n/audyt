from flask import Flask, render_template, request, redirect, url_for, session, make_response
import pyotp
import qrcode
from io import BytesIO
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = 'supersecretkey'
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# W rzeczywistej aplikacji użyj bazy danych do przechowywania danych użytkowników i sekretnych kluczy
users = {
    'user1': {
        'password': 'password123',
        'secret': pyotp.random_base32()
    }
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        
        if user and user['password'] == password:
            session['username'] = username
            return redirect(url_for('verify'))
        else:
            return 'Invalid username or password'
    
    return render_template('login.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = users[username]
    
    if request.method == 'POST':
        token = request.form['token']
        totp = pyotp.TOTP(user['secret'])
        
        if totp.verify(token):
            session['authenticated'] = True
            return redirect(url_for('protected'))
        else:
            return 'Invalid token'
    
    # Generate QR code
    totp = pyotp.TOTP(user['secret'])
    uri = totp.provisioning_uri(name=username, issuer_name='MyApp')
    img = qrcode.make(uri)
    img_bytes = BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    img_b64 = img_bytes.getvalue()
    img_data = base64.b64encode(img_b64).decode()

    return render_template('verify.html', qr_code_data=img_data)

@app.route('/protected')
def protected():
    if 'authenticated' in session:
        return render_template('protected.html')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/setup')
def setup():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('setup.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        text = request.form['text']
        encrypted_text = cipher_suite.encrypt(text.encode()).decode()
        return render_template('encrypt.html', encrypted_text=encrypted_text)
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        encrypted_text = request.form['encrypted_text']
        try:
            decrypted_text = cipher_suite.decrypt(encrypted_text.encode()).decode()
        except:
            decrypted_text = "Invalid encrypted text"
        return render_template('decrypt.html', decrypted_text=decrypted_text)
    return render_template('decrypt.html')

if __name__ == '__main__':
    app.run(debug=True)
