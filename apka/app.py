import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import hashlib
import requests
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# --- KONFIGURACJA ---
app.config['SECRET_KEY'] = 'bardzo-tajny-klucz-zmien-go-w-produkcji'  # Potrzebne do sesji logowania
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Baza danych w pliku
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'zip', 'rar', '7z'}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Gdzie przekierować, jak ktoś nie jest zalogowany


# --- BAZA DANYCH (MODELE) ---

# Tabela Użytkowników
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)  # Relacja z plikami


# Tabela Plików
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    filepath = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Kto wrzucił


# Funkcja pomocnicza dla Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


API_KEY = os.getenv('VT_API_KEY')


def check_virus_total(filepath):
    """
    Wersja RESTRYKCYJNA: Blokuje pobieranie przy jakimkolwiek błędzie API.
    """
    # 1. Obliczamy hash pliku
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    # 2. Pytamy VirusTotal
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    # Pobieramy klucz z .env (lub wpisz go tu ręcznie jeśli nie używasz .env)
    api_key_val = os.getenv('VT_API_KEY')

    if not api_key_val:
        return False, "BŁĄD KRYTYCZNY: Brak klucza API w konfiguracji serwera!"

    headers = {"x-apikey": api_key_val}

    try:
        response = requests.get(url, headers=headers, timeout=10)  # Timeout 10 sekund
    except requests.exceptions.RequestException:
        # Błąd połączenia (brak internetu, awaria DNS itp.)
        return False, "Błąd połączenia z serwerem antywirusowym. Pobieranie zablokowane dla bezpieczeństwa."

    # 3. Analiza odpowiedzi
    if response.status_code == 200:
        # Sukces - mamy raport
        json_response = response.json()
        stats = json_response['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']

        if malicious > 0:
            return False, f"ZAGROŻENIE: Wykryto wirusa przez {malicious} silników!"
        else:
            return True, "Plik czysty."

    elif response.status_code == 404:
        # Plik nieznany (nie ma go w bazie).
        # Tutaj musisz podjąć decyzję:
        return False, #"Plik nieznany - blokada bezpieczeństwa."  <-- Opcja super bezpieczna

    elif response.status_code == 401 or response.status_code == 403:
        # Błąd klucza API (zły klucz lub brak uprawnień)
        return False, "Błąd autoryzacji API (zły klucz). Pobieranie zablokowane."

    elif response.status_code == 429:
        # Przekroczono limit zapytań
        return False, "Serwer przekroczył limit skanowań na minutę/dzień. Spróbuj później."

    else:
        # Inne błędy serwera (np. 500)
        return False, f"Niespodziewany błąd VirusTotal (Kod: {response.status_code})."



@app.route('/')
def index():
    files = File.query.all()  # Pobierz wszystkie pliki z bazy
    return render_template('index.html', files=files)


# Rejestracja
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Sprawdź czy użytkownik istnieje
        user = User.query.filter_by(username=username).first()
        if user:
            # --- ZMIANA TUTAJ ---
            flash('Taki użytkownik już istnieje! Wybierz inną nazwę.', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, password=generate_password_hash(password, method='scrypt'))
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash('Konto utworzone pomyślnie!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')


# Logowanie
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Zalogowano pomyślnie!', 'success')  # Opcjonalnie: zielony komunikat po sukcesie
            return redirect(url_for('index'))
        else:
            # --- TO JEST ZMIANA ---
            # Zamiast return "Błąd...", wysyłamy komunikat do systemu...
            flash('Błędny login lub hasło. Spróbuj ponownie.', 'error')
            # ...i odświeżamy stronę logowania, żeby go wyświetlić.
            return redirect(url_for('login'))

    return render_template('login.html')


# Wylogowanie
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Wysyłanie plików (Tylko dla zalogowanych)
@app.route('/upload', methods=['GET', 'POST'])
@login_required  # <--- To zabezpiecza widok
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'Brak pliku'
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            return 'Błąd pliku'

        filename = secure_filename(file.filename)
        # Zapisz plik na dysku
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Zapisz informacje w bazie danych (przypisz do current_user)
        new_file = File(filename=filename, filepath=filename, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()

        return redirect(url_for('index'))
    return render_template('upload.html')


# Pobieranie plików (Dla każdego)
@app.route('/uploads/<filename>')
def download_file(filename):
    # Sprawdzamy, czy użytkownik zaznaczył suwak (parametr w linku ?safe=on)
    safe_mode = request.args.get('safe')

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if safe_mode == 'on':
        is_safe, message = check_virus_total(file_path)

        if not is_safe:
            # Jeśli wirus - wyświetlamy tylko komunikat (flash) i wracamy na główną
            flash(f'⛔ BLOKADA: {message}', 'error')
            return redirect(url_for('index'))
        else:
            # Jeśli bezpieczny - wyświetlamy info i pobieramy
            flash(f'✅ {message}', 'success')

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()


        upload_folder_name = app.config['UPLOAD_FOLDER']

        if not os.path.exists(upload_folder_name):
            os.makedirs(upload_folder_name)

    app.run(debug=True, host="0.0.0.0")
