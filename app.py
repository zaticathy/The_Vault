from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os
import base64

# Initialize app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'zatiafrivault-secret-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zatiafrivault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

# Generate encryption key
key = Fernet.generate_key()
cipher = Fernet(key)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    organization = db.Column(db.String(200), nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    room = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Routes
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = user.username
            session['email'] = user.email
            return redirect(url_for('chat'))
        else:
            error = 'Invalid email or password'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        organization = request.form.get('organization')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            error = 'Email already registered'
        else:
            hashed_password = bcrypt.generate_password_hash(
                password).decode('utf-8')
            new_user = User(
                username=username,
                email=email,
                password=hashed_password,
                organization=organization
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Socket Events
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('status', {
        'message': f"{session.get('username')} has joined the room"
    }, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    emit('status', {
        'message': f"{session.get('username')} has left the room"
    }, room=room)

@socketio.on('send_message')
def handle_message(data):
    room = data['room']
    message = data['message']
    username = session.get('username')

    # Encrypt message before storing
    encrypted = cipher.encrypt(message.encode()).decode()

    # Store encrypted message in database
    new_message = Message(
        sender=username,
        room=room,
        content=encrypted
    )
    db.session.add(new_message)
    db.session.commit()

    # Send decrypted message to room
    emit('receive_message', {
        'username': username,
        'message': message,
        'encrypted': encrypted[:50] + '...'
    }, room=room)

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    socketio.run(app, debug=True)