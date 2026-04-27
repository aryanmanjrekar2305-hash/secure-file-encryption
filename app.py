from flask import Flask, request, render_template_string, send_file, flash, redirect, url_for
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
from io import BytesIO
import zipfile

app = Flask(__name__)
app.secret_key = "secure_secret_key"


# ---------- KEY GENERATION ----------
def generate_key(password):
    password = password.encode()
    salt = b"secure_salt"

    kdf = pbkdf2_hmac(
        "sha256",
        password,
        salt,
        100000
    )

    return urlsafe_b64encode(kdf)


# ---------- HTML UI ----------
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure File Encryption Tool</title>

<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: Arial, sans-serif;
}

body {
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    background-image: url('https://images.unsplash.com/photo-1510511459019-5dda7724fd87');
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
}

.overlay {
    position: absolute;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.70);
}

.container {
    position: relative;
    z-index: 2;
    width: 92%;
    max-width: 600px;
    background: rgba(255,255,255,0.08);
    backdrop-filter: blur(14px);
    border-radius: 22px;
    padding: 35px;
    color: white;
    box-shadow: 0 10px 40px rgba(0,0,0,0.4);
    text-align: center;
}

h1 {
    font-size: 30px;
    margin-bottom: 10px;
}

.subtitle {
    color: #dddddd;
    margin-bottom: 20px;
}

input[type="file"],
input[type="password"] {
    width: 100%;
    padding: 14px;
    border: none;
    border-radius: 10px;
    margin-bottom: 14px;
    font-size: 15px;
}

.password-box {
    position: relative;
}

.show-btn {
    width: 100%;
    padding: 10px;
    border: none;
    border-radius: 10px;
    background: #444;
    color: white;
    cursor: pointer;
    margin-bottom: 12px;
}

.password-tip {
    font-size: 13px;
    color: #cccccc;
    text-align: left;
    margin-bottom: 8px;
}

.strength {
    margin-bottom: 15px;
    font-size: 14px;
    text-align: left;
}

.file-count {
    margin-bottom: 15px;
    font-size: 14px;
    color: #f1f1f1;
}

.btn {
    width: 100%;
    padding: 14px;
    border: none;
    border-radius: 10px;
    margin-top: 10px;
    font-size: 16px;
    font-weight: bold;
    cursor: pointer;
}

.encrypt {
    background: #27ae60;
    color: white;
}

.decrypt {
    background: #2980b9;
    color: white;
}

.msg {
    background: rgba(255,255,255,0.12);
    padding: 12px;
    border-radius: 10px;
    margin-bottom: 15px;
    color: #ffd166;
}


</style>
</head>
<body>

<div class="overlay"></div>

<div class="container">
    <h1>Secure File Encryption Tool</h1>
    <div class="subtitle">Upload multiple files and encrypt or decrypt securely</div>

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <div class="msg">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    <form method="POST" enctype="multipart/form-data">
        <input type="file" id="fileInput" name="file" multiple accept="*/*" required onchange="updateFileCount()">

        <div class="file-count" id="fileCount">No files selected</div>

        <div class="password-box">
            <input type="password" id="password" name="password" placeholder="Enter Strong Password" required onkeyup="checkStrength()">
            <button type="button" class="show-btn" onclick="togglePassword()">👁 Show / Hide Password</button>
        </div>

        <div class="password-tip">
            Use 8+ characters, uppercase, number and special symbol.
        </div>

        <div class="strength" id="strengthText">Password Strength: —</div>

        <button class="btn encrypt" name="action" value="encrypt">🔒 Encrypt Files</button>
        <button class="btn decrypt" name="action" value="decrypt">🔓 Decrypt Files</button>
    </form>

    
</div>

<script>
function togglePassword() {
    let pass = document.getElementById("password");
    if (pass.type === "password") {
        pass.type = "text";
    } else {
        pass.type = "password";
    }
}

function updateFileCount() {
    let files = document.getElementById("fileInput").files;
    let count = files.length;
    let text = count === 0 ? "No files selected" : count + " file(s) selected";
    document.getElementById("fileCount").innerText = text;
}

function checkStrength() {
    let password = document.getElementById("password").value;
    let strength = 0;

    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[!@#$%^&*]/.test(password)) strength++;

    let text = "Password Strength: ";

    if (strength <= 1) text += "Weak";
    else if (strength == 2) text += "Medium";
    else if (strength == 3) text += "Strong";
    else text += "Very Strong";

    document.getElementById("strengthText").innerText = text;
}
</script>

</body>
</html>
"""


# ---------- ROUTE ----------
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        uploaded_files = request.files.getlist("file")
        password = request.form.get("password", "")
        action = request.form.get("action")

        if not uploaded_files or password == "":
            flash("Please select files and enter password.")
            return redirect(url_for("home"))

        try:
            key = generate_key(password)
            fernet = Fernet(key)
            zip_buffer = BytesIO()
            processed_files = 0

            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                for uploaded_file in uploaded_files:
                    file_data = uploaded_file.read()
                    filename = uploaded_file.filename

                    try:
                        if action == "encrypt":
                            output_data = fernet.encrypt(file_data)
                            output_name = filename + ".enc"

                        elif action == "decrypt":
                            if not filename.endswith(".enc"):
                                flash(f"{filename} is not a .enc file")
                                continue

                            output_data = fernet.decrypt(file_data)
                            output_name = filename.replace(".enc", "")

                        else:
                            flash("Invalid action.")
                            return redirect(url_for("home"))

                        zip_file.writestr(output_name, output_data)
                        processed_files += 1

                    except Exception as e:
                        if action == "decrypt":
                            flash(f"Failed to decrypt: {filename} → Wrong password or invalid encrypted file.")
                        else:
                            flash(f"Failed to encrypt: {filename}")
                        continue

            if processed_files == 0:
                flash("No valid files processed. Wrong password or invalid file.")
                return redirect(url_for("home"))

            zip_buffer.seek(0)

            if action == "encrypt":
                final_name = "encrypted_files.zip"
                flash("Encryption Successful")
            else:
                final_name = "decrypted_files.zip"
                flash("Decryption Successful")

            return send_file(
                zip_buffer,
                as_attachment=True,
                download_name=final_name,
                mimetype="application/zip"
            )

        except Exception:
            flash("Operation failed. Check password or file type.")
            return redirect(url_for("home"))

    return render_template_string(HTML)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
