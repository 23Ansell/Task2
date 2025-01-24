from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash # CHATGPT - Responsible for hashing passwords
import sqlite3
import uuid
from datetime import datetime


app = Flask(__name__)
app.secret_key = uuid.uuid4().hex


def is_logged_in():
    return 'user_id' in session


def is_admin():
    if is_logged_in():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        return user['is_admin']
    else:
        pass


def get_db_connection():
    db_path = 'database.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    return render_template('index.html', is_logged_in=is_logged_in)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Email already registered. Please use a different email or log in.', 'danger')
            conn.close()
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
                       (full_name, email, hashed_password))
        conn.commit()
        conn.close()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['full_name'] = user['full_name']
            flash('You are now logged in', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', is_logged_in=is_logged_in)


if __name__ == '__main__':
    app.run(debug=True)