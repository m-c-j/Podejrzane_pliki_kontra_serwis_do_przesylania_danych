import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import hashlib
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify

load_dotenv()
app = Flask(__name__)

# --- KONFIGURACJA ---
app.config['SECRET_KEY'] = 'bardzo-tajny-klucz-serio-tajne'  # Potrzebne do sesji logowania
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Baza danych w pliku
app.config['UPLOAD_FOLDER'] = 'uploads'

# LIMIT: Maksymalnie 32 MB (32 * 1024 * 1024 bajtów)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'zip', 'rar', '7z', 'exe'}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


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
    Statusy: 'SAFE', 'DANGER', 'ERROR', 'QUEUED', 'TOO_LARGE'
    """
    api_key_val = os.getenv('VT_API_KEY')
    if not api_key_val:
        return 'ERROR', "Brak klucza API."

    file_size_mb = os.path.getsize(filepath) / (1024 * 1024)  # Rozmiar w MB
    if file_size_mb > 32:
        return 'TOO_LARGE', f"Plik ma {file_size_mb:.1f}MB. Limit skanowania to 32MB."

    # 1. Obliczamy hash
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        file_content = f.read()
        sha256_hash.update(file_content)
    file_hash = sha256_hash.hexdigest()

    # 2. Sprawdzamy w bazie (GET)
    url_check = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key_val}

    try:
        response = requests.get(url_check, headers=headers, timeout=10)
    except requests.exceptions.RequestException:
        return 'ERROR', "Błąd połączenia z serwerem antywirusowym."

    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        if malicious > 0:
            return 'DANGER', f"ZAGROŻENIE: Wykryto wirusa ({malicious} silników)!"
        else:
            return 'SAFE', "Plik czysty (znaleziony w bazie)."

    elif response.status_code == 404:
        # Próba wysłania (POST)
        files = {'file': (os.path.basename(filepath), file_content)}
        url_upload = "https://www.virustotal.com/api/v3/files"

        try:
            upload_response = requests.post(url_upload, headers=headers, files=files)

            if upload_response.status_code == 200:
                return 'QUEUED', "Plik nieznany. Wysłano do analizy. Spróbuj za chwilę."
            elif upload_response.status_code == 413:  # Błąd API "Za duży"
                return 'TOO_LARGE', "Plik jest zbyt duży dla darmowego skanera antywirusowego."
            else:
                return 'ERROR', f"Błąd wysyłania (Kod: {upload_response.status_code})."
        except Exception as e:
            return 'ERROR', f"Błąd: {str(e)}"

    elif response.status_code == 401:
        return 'ERROR', "Zły klucz API."
    elif response.status_code == 429:
        return 'ERROR', "Przekroczono limit zapytań."
    else:
        return 'ERROR', f"Niespodziewany błąd (Kod: {response.status_code})."


# Obsługa błędu "Za duży plik"
@app.errorhandler(413)
def request_entity_too_large(error):
    flash('Plik jest zbyt duży! Maksymalny rozmiar to 32MB.', 'error')
    return redirect(request.url), 413

@app.route('/')
def index():
    files = File.query.all()
    return render_template('index.html', files=files)


# Rejestracja
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
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
            flash('Błędny login lub hasło. Spróbuj ponownie.', 'error')
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
    safe_mode = request.args.get('safe')
    confirm = request.args.get('confirm')

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if safe_mode == 'on':
        status, message = check_virus_total(file_path)

        # 1. WIRUS LUB BŁĄD
        if status == 'DANGER' or status == 'ERROR':
            flash(f'⛔ BLOKADA: {message}', 'error')
            return redirect(url_for('index'))

        # 2. TRWA SKANOWANIE (Nowy status)
        if status == 'QUEUED':
            flash(f'⏳ {message} Spróbuj pobrać ponownie za 2-3 minuty.', 'warning')
            return redirect(url_for('index'))

        # 3. PLIK CZYSTY
        if status == 'SAFE':
            pass


        if status == 'TOO_LARGE':
            if confirm != 'yes':
                flash(f'⚠️ {message}', 'warning')
                # Dodajemy zmienną 'reason' (powód)
                return render_template('confirm_download.html', filename=filename, reason=message)

            flash(f'⚠️ Pobrałeś duży plik bez skanowania: {message}', 'warning')

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# --- NOWA TRASA API DLA JAVASCRIPTU ---
@app.route('/api/check_file/<filename>')
def check_file_api(filename):
    """
    Sprawdza bezpieczeństwo i zwraca JSON zamiast HTML.
    Używane przez JavaScript do wyświetlania komunikatów bez odświeżania.
    """
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    status, message = check_virus_total(file_path)

    return jsonify({
        'status': status,
        'message': message,
        'filename': filename
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()


        upload_folder_name = app.config['UPLOAD_FOLDER']

        if not os.path.exists(upload_folder_name):
            os.makedirs(upload_folder_name)

    app.run(debug=True, host="0.0.0.0")
