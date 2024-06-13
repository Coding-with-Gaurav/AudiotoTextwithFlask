import os
import re
import bcrypt
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from flask_pymongo import PyMongo
import whisper
import pandas as pd
from pydub import AudioSegment

app = Flask(__name__)
app.secret_key = "AudiotoText" 

# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/audiototext"
mongo = PyMongo(app)
users_collection = mongo.db.users

def extract_information(text):
    text = text.replace("wait", "weight")
    pattern = re.compile(
        r'sample\s*id\s*([a-z\s]*\w+)\s*(?:dash|-)\s*([a-z0-9]+)\s*(?:,|\s+)?\s*weight\s*([\d.]+)', 
        re.IGNORECASE
    )
    matches = pattern.findall(text)

    data = []
    for match in matches:
        sample_id = match[0].strip().upper().replace(" ", "") + "-" + match[1].strip()
        sample_id = sample_id.replace("DASH", "-").replace(",", "").replace(".", "")
        weight = match[2].strip()
        data.append((sample_id, weight))
    return data

def convert_to_wav(mp4_file_path):
    wav_file_path = mp4_file_path.replace(".mp4", ".wav")
    audio = AudioSegment.from_file(mp4_file_path, format="mp4")
    audio.export(wav_file_path, format="wav")
    return wav_file_path

def audio_file_to_text(wav_file_path):
    model = whisper.load_model("base")
    result = model.transcribe(wav_file_path)
    text = result['text']
    return text

def save_to_excel(data, file_name="sample_file.xlsx"):
    if data:
        if os.path.exists(file_name):
            df_existing = pd.read_excel(file_name)
            df_new = pd.DataFrame(data, columns=["Sample ID", "Weight"])
            df_combined = pd.concat([df_existing, df_new], ignore_index=True)
            df_combined.to_excel(file_name, index=False)
        else:
            df = pd.DataFrame(data, columns=["Sample ID", "Weight"])
            df.to_excel(file_name, index=False)

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html')
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_collection.find_one({"username": username})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        if users_collection.find_one({"username": username}):
            flash('Username already exists', 'danger')
        else:
            users_collection.insert_one({"username": username, "password": hashed_password})
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'files' not in request.files:
        flash('No file part')
        return redirect(request.url)

    files = request.files.getlist('files')
    data = []

    for file in files:
        if file.filename.endswith(".mp4"):
            file_path = os.path.join("uploads", file.filename)
            file.save(file_path)
            wav_file_path = convert_to_wav(file_path)
            text = audio_file_to_text(wav_file_path)
            if text:
                extracted_data = extract_information(text)
                if extracted_data:
                    data.extend(extracted_data)
            os.remove(wav_file_path)
            os.remove(file_path)
        else:
            flash(f"Unsupported file format: {file.filename}")

    if data:
        save_to_excel(data)
        flash('Data successfully processed and saved to Excel file.', 'success')
    else:
        flash('No data to save to Excel.', 'warning')

    return redirect(url_for('index'))

@app.route('/view')
def view():
    if 'username' not in session:
        return redirect(url_for('login'))

    if os.path.exists("sample_file.xlsx"):
        df = pd.read_excel("sample_file.xlsx")
        df.columns = [col.replace(' ', '') for col in df.columns]
        return render_template('view.html', tables=df.to_dict(orient='records'))
    else:
        flash('No Excel file found.', 'warning')
        return redirect(url_for('index'))

@app.route('/download')
def download():
    if 'username' not in session:
        return redirect(url_for('login'))

    if os.path.exists("sample_file.xlsx"):
        return send_file("sample_file.xlsx", as_attachment=True)
    else:
        flash('No Excel file found.', 'warning')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
