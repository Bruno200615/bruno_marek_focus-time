# Importovanie potrebných knižníc z Flasku a jeho rozšírení
from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

# Inicializácia Flask aplikácie
app = Flask(__name__)

# Nastavenie tajného kľúča (napr. pre sessions a flash správy)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'

# Nastavenie cesty k databáze SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Inicializácia databázy, hashovania hesiel a systému prihlásenia
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Ak nie je používateľ prihlásený, presmeruje ho na túto stránku

# Definícia modelu používateľa v databáze
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # Primárny kľúč
    username = db.Column(db.String(20), unique=True, nullable=False)  # Meno používateľa, musí byť unikátne
    password = db.Column(db.String(60), nullable=False)  # Zašifrované heslo

# Funkcia, ktorú používa Flask-Login na načítanie používateľa podľa ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Hlavná stránka (presmeruje na login)
@app.route('/')
def home():
    return redirect(url_for('login'))

# Registračná stránka
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Ak je už používateľ prihlásený, presmeruje ho na dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Ak bol odoslaný formulár
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Skontroluje, či už meno existuje v databáze
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')  # Zobrazí chybovú hlášku
            return redirect(url_for('register'))
        
        # Zašifruje heslo a uloží používateľa do databázy
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created! Please login', 'success')  # Zobrazí úspešnú hlášku
        return redirect(url_for('login'))
    
    # Ak GET požiadavka, zobrazí registračný formulár
    return render_template('register.html')

# Prihlasovacia stránka
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Ak je používateľ už prihlásený, presmeruje ho na dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Spracovanie prihlasovacieho formulára
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Skontroluje, či používateľ existuje a či heslo sedí
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)  # Prihlási používateľa
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check username/password', 'danger')  # Zobrazí chybovú hlášku
    
    return render_template('login.html')  # Zobrazí prihlasovací formulár

# Odhlásenie používateľa
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))  # Presmeruje na login po odhlásení

# Chránená stránka - dashboard (iba pre prihlásených používateľov)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

# Spustenie aplikácie
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Vytvorí databázové tabuľky, ak ešte neexistujú
    app.run(debug=True)  # Spustí Flask server s debug režimom (zobrazovanie chýb)
