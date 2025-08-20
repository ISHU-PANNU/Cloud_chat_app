from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from datetime import datetime
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
socketio = SocketIO(app, cors_allowed_origins="*")  # SocketIO for real-time messaging

# ---------------- MODELS ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    avatar = db.Column(db.String(200), default="")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(150))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ----------------
@app.route('/')
@login_required
def home():
    users = User.query.all()
    return render_template('chat.html', users=users)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash("Login failed!")
    return render_template('login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists!")
            return redirect(url_for('signup'))

        password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        avatar_url = f"https://api.dicebear.com/7.x/bottts/svg?seed={random.randint(1,10000)}"
        new_user = User(username=username, password=password, avatar=avatar_url)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! Please login.")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------- SOCKET EVENTS ----------------
@socketio.on('send_message')
def handle_send_message(data):
    # Save message in DB
    new_msg = Message(sender=current_user.username, content=data['message'])
    db.session.add(new_msg)
    db.session.commit()
    # Broadcast message to all connected clients
    emit('receive_message', {
        'sender': new_msg.sender,
        'content': new_msg.content,
        'timestamp': new_msg.timestamp.strftime('%H:%M:%S')
    }, broadcast=True)

# ---------------- MAIN ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

@app.route('/create-db')
def create_db():
    db.create_all()  # This creates all tables defined in your models
    return "Database tables created!"
