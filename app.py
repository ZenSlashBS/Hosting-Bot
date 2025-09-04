from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import os
import subprocess
import threading
from datetime import datetime
import sqlite3
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = 'wtf'
app.config['UPLOAD_FOLDER'] = 'user_bots'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def init_db():
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE,
                     password TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS files
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id INTEGER,
                     filename TEXT,
                     filetype TEXT,
                     upload_date TEXT,
                     FOREIGN KEY(user_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS processes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     file_id INTEGER,
                     pid INTEGER,
                     start_time TEXT,
                     FOREIGN KEY(file_id) REFERENCES files(id))''')
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database init error: {str(e)}")
        raise

init_db()

running_processes = {}
process_logs = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'py', 'js', 'zip'}

@app.route('/')
def index():
    try:
        logger.debug("Accessing index route")
        if 'user_id' not in session:
            logger.debug("No user_id in session, redirecting to login")
            return redirect(url_for('login'))
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT id, filename, filetype FROM files WHERE user_id = ?', (session['user_id'],))
        files = c.fetchall()
        conn.close()
        file_status = []
        for file in files:
            file_id, filename, filetype = file
            is_running = file_id in running_processes and running_processes[file_id].poll() is None
            file_status.append({'id': file_id, 'name': filename, 'type': filetype, 'running': is_running})
        logger.debug(f"Rendering index.html with files: {file_status}")
        return render_template('index.html', files=file_status, username=session.get('username'))
    except Exception as e:
        logger.error(f"Index error: {str(e)}")
        return f"Internal Server Error: {str(e)}", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        logger.debug("Accessing login route")
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            conn = sqlite3.connect('bot_data.db')
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE username = ? AND password = ?', (username, password))
            user = c.fetchone()
            conn.close()
            if user:
                session['user_id'] = user[0]
                session['username'] = username
                logger.debug(f"User {username} logged in")
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials', 'error')
                logger.warning(f"Failed login attempt for {username}")
        logger.debug("Rendering login.html")
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return f"Internal Server Error: {str(e)}", 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        logger.debug("Accessing register route")
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            conn = sqlite3.connect('bot_data.db')
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
                conn.commit()
                flash('Registration successful! Please login.', 'success')
                logger.debug(f"User {username} registered")
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists', 'error')
                logger.warning(f"Registration failed: Username {username} exists")
            finally:
                conn.close()
        logger.debug("Rendering register.html")
        return render_template('register.html')
    except Exception as e:
        logger.error(f"Register error: {str(e)}")
        return f"Internal Server Error: {str(e)}", 500

@app.route('/logout')
def logout():
    try:
        logger.debug("Accessing logout route")
        session.clear()
        logger.debug("User logged out")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return f"Internal Server Error: {str(e)}", 500

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        logger.debug("Accessing upload route")
        if 'user_id' not in session:
            logger.debug("No user_id in session, redirecting to login")
            return redirect(url_for('login'))
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (session['user_id'],))
        file_count = c.fetchone()[0]
        if file_count >= 5:
            conn.close()
            flash('You can only upload up to 5 files', 'error')
            logger.warning("File upload limit reached")
            return redirect(url_for('index'))
        if 'file' not in request.files:
            conn.close()
            flash('No file selected', 'error')
            logger.warning("No file selected for upload")
            return redirect(url_for('index'))
        file = request.files['file']
        if file.filename == '':
            conn.close()
            flash('No file selected', 'error')
            logger.warning("Empty file name in upload")
            return redirect(url_for('index'))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filetype = filename.rsplit('.', 1)[1].lower()
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
            os.makedirs(user_folder, exist_ok=True)
            filepath = os.path.join(user_folder, filename)
            file.save(filepath)
            c.execute('INSERT INTO files (user_id, filename, filetype, upload_date) VALUES (?, ?, ?, ?)',
                      (session['user_id'], filename, filetype, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            flash('File uploaded successfully', 'success')
            logger.debug(f"File {filename} uploaded by user {session['user_id']}")
            return redirect(url_for('index'))
        conn.close()
        flash('Invalid file type. Only .py, .js, and .zip files are allowed', 'error')
        logger.warning(f"Invalid file type uploaded: {file.filename}")
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return f"Internal Server Error: {str(e)}", 500

@app.route('/control/<int:file_id>/<action>')
def control_file(file_id, action):
    try:
        logger.debug(f"Accessing control route for file_id={file_id}, action={action}")
        if 'user_id' not in session:
            logger.debug("No user_id in session, redirecting to login")
            return redirect(url_for('login'))
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT filename, filetype FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id']))
        file = c.fetchone()
        if not file:
            conn.close()
            flash('File not found', 'error')
            logger.warning(f"File {file_id} not found for user {session['user_id']}")
            return redirect(url_for('index'))
        filename, filetype = file
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
        filepath = os.path.join(user_folder, filename)
        if action == 'start':
            if file_id in running_processes and running_processes[file_id].poll() is None:
                conn.close()
                flash('This file is already running', 'error')
                logger.warning(f"File {file_id} already running")
                return redirect(url_for('index'))
            try:
                if filetype == 'py':
                    process = subprocess.Popen(['python', filepath], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                elif filetype == 'js':
                    process = subprocess.Popen(['node', filepath], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                else:
                    conn.close()
                    flash('Unsupported file type', 'error')
                    logger.warning(f"Unsupported file type for {file_id}: {filetype}")
                    return redirect(url_for('index'))
                running_processes[file_id] = process
                process_logs[file_id] = []
                threading.Thread(target=collect_logs, args=(file_id, process)).start()
                c.execute('INSERT INTO processes (file_id, pid, start_time) VALUES (?, ?, ?)',
                          (file_id, process.pid, datetime.now().isoformat()))
                conn.commit()
                conn.close()
                flash('Script started successfully', 'success')
                logger.debug(f"Script {filename} started with pid {process.pid}")
                return redirect(url_for('index'))
            except Exception as e:
                conn.close()
                flash(f'Error starting script: {str(e)}', 'error')
                logger.error(f"Error starting script {file_id}: {str(e)}")
                return redirect(url_for('index'))
        elif action == 'stop':
            if file_id not in running_processes:
                conn.close()
                flash('Script is not running', 'error')
                logger.warning(f"Script {file_id} not running")
                return redirect(url_for('index'))
            process = running_processes[file_id]
            process.terminate()
            del running_processes[file_id]
            if file_id in process_logs:
                del process_logs[file_id]
            c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
            conn.commit()
            conn.close()
            flash('Script stopped successfully', 'success')
            logger.debug(f"Script {file_id} stopped")
            return redirect(url_for('index'))
        conn.close()
        flash('Invalid action', 'error')
        logger.warning(f"Invalid action for file {file_id}: {action}")
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Control error: {str(e)}")
        return f"Internal Server Error: {str(e)}", 500

def collect_logs(file_id, process):
    try:
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                process_logs[file_id].append(output.strip())
                logger.debug(f"Log for {file_id}: {output.strip()}")
    except Exception as e:
        logger.error(f"Log collection error for {file_id}: {str(e)}")

@app.route('/logs/<int:file_id>')
def get_logs(file_id):
    try:
        logger.debug(f"Accessing logs for file_id={file_id}")
        if 'user_id' not in session:
            logger.debug("No user_id in session, redirecting to login")
            return redirect(url_for('login'))
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT 1 FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id']))
        if not c.fetchone():
            conn.close()
            flash('Access denied', 'error')
            logger.warning(f"Access denied for logs of file {file_id}")
            return redirect(url_for('index'))
        conn.close()
        if file_id not in process_logs:
            logger.debug(f"No logs for file {file_id}")
            return jsonify([])
        logger.debug(f"Returning logs for file {file_id}")
        return jsonify(process_logs[file_id][-100:])
    except Exception as e:
        logger.error(f"Logs error: {str(e)}")
        return f"Internal Server Error: {str(e)}", 500

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    try:
        logger.debug(f"Accessing delete route for file_id={file_id}")
        if 'user_id' not in session:
            logger.debug("No user_id in session, redirecting to login")
            return redirect(url_for('login'))
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT filename FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id']))
        file = c.fetchone()
        if not file:
            conn.close()
            flash('File not found', 'error')
            logger.warning(f"File {file_id} not found for deletion")
            return redirect(url_for('index'))
        filename = file[0]
        if file_id in running_processes:
            running_processes[file_id].terminate()
            del running_processes[file_id]
            if file_id in process_logs:
                del process_logs[file_id]
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
        filepath = os.path.join(user_folder, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
        conn.commit()
        conn.close()
        flash('File deleted successfully', 'success')
        logger.debug(f"File {file_id} deleted")
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Delete error: {str(e)}")
        return f"Internal Server Error: {str(e)}", 500

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
