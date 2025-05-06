from flask import Flask, render_template, url_for, redirect, request, flash, jsonify
import openai
from flask_login import login_user, login_required, logout_user, current_user
from extensions import db, bcrypt, login_manager
from models import User, Session, SessionEvent
from chat.routes import chat_bp
from datetime import datetime, timezone
from flask import Flask, render_template, url_for, redirect, request, flash, jsonify
import openai
import os
from dotenv import load_dotenv



def create_app():
    load_dotenv()
    
    app = Flask(__name__)

    # Config
    app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    openai.api_key ="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"
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    # Register blueprints
    app.register_blueprint(chat_bp)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

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
        sessions = (
            Session.query
            .filter(Session.user_id == current_user.id, Session.ended_at.isnot(None))
            .order_by(Session.started_at.desc())
            .all()
        )
        return render_template('dashboard.html', username=current_user.username, sessions=sessions)

    # Session endpoints
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
        session.ended_at = datetime.utcnow()
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
        SessionEvent.query.filter_by(session_id=session_id).delete()
        session = Session.query.filter_by(id=session_id, user_id=current_user.id).first_or_404()
        db.session.delete(session)
        db.session.commit()
        return jsonify({'status': 'deleted'}), 200

    with app.app_context():
        db.create_all()

    return app


if __name__ == '__main__':
    create_app().run(debug=True)
