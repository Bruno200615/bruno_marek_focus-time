from datetime import datetime
from flask import Flask, render_template, url_for, redirect, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Initialize extensions
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    sessions = db.relationship('Session', backref='user', lazy=True)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note = db.Column(db.String(200), nullable=True)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)
    events = db.relationship('SessionEvent', backref='session', lazy=True)

class SessionEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    event_type = db.Column(db.String(10), nullable=False)  # 'start' or 'stop'
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Basic auth & pages
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login failed. Check username/password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Retrieve only finished sessions
    sessions = (
        Session.query
        .filter(Session.user_id == current_user.id, Session.ended_at.isnot(None))
        .order_by(Session.started_at.desc())
        .all()
    )
    return render_template('dashboard.html', username=current_user.username, sessions=sessions)

# Session control endpoints
@app.route('/session/start', methods=['POST'])
@login_required
def session_start():
    sess = Session(user=current_user)
    db.session.add(sess)
    db.session.commit()
    evt = SessionEvent(session_id=sess.id, event_type='start')
    db.session.add(evt)
    db.session.commit()
    return jsonify({'session_id': sess.id}), 201

@app.route('/session/stop', methods=['POST'])
@login_required
def session_stop():
    data = request.get_json() or {}
    sess_id = data.get('session_id')
    session = Session.query.filter_by(id=sess_id, user_id=current_user.id).first_or_404()
    evt = SessionEvent(session_id=session.id, event_type='stop')
    db.session.add(evt)
    db.session.commit()
    return jsonify({'status': 'ok'}), 201

@app.route('/session/save', methods=['POST'])
@login_required
def session_save():
    data = request.get_json() or {}
    sess_id = data.get('session_id')
    note = data.get('note', '')
    session = Session.query.filter_by(id=sess_id, user_id=current_user.id).first_or_404()
    session.note = note
    session.ended_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'status': 'ok'}), 200

@app.route('/session/reset', methods=['POST'])
@login_required
def session_reset():
    data = request.get_json() or {}
    sess_id = data.get('session_id')
    session = Session.query.filter_by(id=sess_id, user_id=current_user.id).first_or_404()
    SessionEvent.query.filter_by(session_id=session.id).delete()
    db.session.delete(session)
    db.session.commit()
    return jsonify({'status': 'ok'}), 200


@app.route('/session/delete', methods=['POST'])
@login_required
def session_delete():
    data = request.get_json() or {}
    session_id = data.get('session_id')
    
    # Najprv vymaž eventy
    SessionEvent.query.filter_by(session_id=session_id).delete()
    
    # Potom vymaž session
    session = Session.query.filter_by(id=session_id, user_id=current_user.id).first_or_404()
    db.session.delete(session)
    
    db.session.commit()
    return jsonify({'status': 'deleted'}), 200

# Run server
def main():
    with app.app_context():
        # Drop and recreate tables to apply new schema
        db.drop_all()
        db.create_all()
    app.run(debug=True)

if __name__ == '__main__':
    main()
