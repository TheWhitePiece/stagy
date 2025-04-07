from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from functools import wraps
import os
import datetime
import json
import hashlib
import secrets
from stegy import (
    USERS, initialize_logs, log_activity, hash_password,
    encode_text, decode_text,
    encode_image, decode_image,
    encode_audio, decode_audio,
    encode_video, decode_video
)

# Initialize Flask app with strong security configurations
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a strong random secret key
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit file uploads to 16MB
app.permanent_session_lifetime = datetime.timedelta(minutes=30)  # Session timeout

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize logging system
initialize_logs()

# Decorator to require login for protected routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator to require admin role
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or 'role' not in session or session['role'] != 'admin':
            flash('Admin privileges required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and USERS[username]["password_hash"] == hash_password(password):
            session.permanent = True
            session['username'] = username
            session['role'] = USERS[username]["role"]
            USERS[username]["last_login"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            log_activity("anonymous", "login_attempt", "user_authentication", "failed", f"Failed login attempt for {username}")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        log_activity(session['username'], "logout", "user_session", "success")
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'], role=session['role'])

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if USERS[session['username']]["password_hash"] == hash_password(current_password):
            if new_password == confirm_password:
                if len(new_password) < 8:
                    flash('Password must be at least 8 characters long', 'danger')
                else:
                    USERS[session['username']]["password_hash"] = hash_password(new_password)
                    flash('Password changed successfully', 'success')
                    log_activity(session['username'], "password_change", "user_account", "success")
            else:
                flash('Passwords do not match', 'danger')
                log_activity(session['username'], "password_change", "user_account", "failed", "Passwords did not match")
        else:
            flash('Current password is incorrect', 'danger')
            log_activity(session['username'], "password_change", "user_account", "failed", "Incorrect current password")
    
    return render_template('profile.html')

@app.route('/text-steganography', methods=['GET', 'POST'])
@login_required
def text_steganography():
    if request.method == 'POST':
        operation = request.form.get('operation')

        if operation == 'encode':
            text_data = request.form.get('text_data')
            if not text_data:
                flash('No data provided for encoding', 'danger')
                return redirect(url_for('text_steganography'))

            # use a static cover file, or let user upload one if you prefer
            cover_path = os.path.join('Sample_cover_files', 'cover_text.txt')
            # ensure the cover‐text directory exists, then check for the cover file
            cover_dir  = 'Sample_cover_files'
            os.makedirs(cover_dir, exist_ok=True)
            cover_path = os.path.join(cover_dir, 'cover_text.txt')
            if not os.path.exists(cover_path):
                flash('Server is missing the cover_text.txt file. Please contact the administrator.', 'danger')
                return redirect(url_for('text_steganography'))


            output_filename = f"stego_text_{datetime.datetime.now():%Y%m%d%H%M%S}.txt"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            try:
                encode_text(cover_path, text_data, output_path, session['username'])
                flash('Text encoding completed successfully', 'success')
                return redirect(url_for('download_file', filename=output_filename))
            except Exception as e:
                flash(f'Encoding failed: {e}', 'danger')
                log_activity(session['username'], 'text_encode', output_filename, 'failed', str(e))
                return redirect(url_for('text_steganography'))

        elif operation == 'decode':
            if 'stego_file' not in request.files:
                flash('No file provided for decoding', 'danger')
                return redirect(url_for('text_steganography'))

            stego_file = request.files['stego_file']
            if stego_file.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('text_steganography'))

            filename = secure_filename(stego_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            stego_file.save(file_path)

            try:
                decoded_text = decode_text(file_path, session['username'])
                return render_template('text_steganography.html', decoded_text=decoded_text)
            except Exception as e:
                flash(f'Decoding failed: {e}', 'danger')
                log_activity(session['username'], 'text_decode', filename, 'failed', str(e))
                return redirect(url_for('text_steganography'))

    return render_template('text_steganography.html')


# @app.route('/image-steganography', methods=['GET', 'POST'])
# @login_required
# def image_steganography():
#     if request.method == 'POST':
#         operation = request.form.get('operation')
        
#         if operation == 'encode':
#             if 'cover_image' not in request.files:
#                 flash('No cover image provided', 'danger')
#                 return redirect(url_for('image_steganography'))
                
#             cover_image = request.files['cover_image']
#             text_data = request.form.get('text_data')
            
#             if cover_image.filename == '' or not text_data:
#                 flash('Missing required data', 'danger')
#                 return redirect(url_for('image_steganography'))
                
#             # Save and process the uploaded file
#             filename = secure_filename(cover_image.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             cover_image.save(file_path)
            
#             # Use your existing encode_img_data function here
#             # For demonstration, we'll create a sample output
#             output_filename = f"stego_image_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.png"
            
#             # Simulate encoding process
#             import shutil
#             shutil.copy(file_path, os.path.join(app.config['UPLOAD_FOLDER'], output_filename))
            
#             log_activity(session['username'], "image_encode", output_filename, "success", f"Encoded {len(text_data)} characters")
#             flash('Image encoding completed successfully', 'success')
#             return redirect(url_for('download_file', filename=output_filename))
            
#         elif operation == 'decode':
#             if 'stego_image' not in request.files:
#                 flash('No stego image provided', 'danger')
#                 return redirect(url_for('image_steganography'))
                
#             stego_image = request.files['stego_image']
#             if stego_image.filename == '':
#                 flash('No file selected', 'danger')
#                 return redirect(url_for('image_steganography'))
                
#             # Save and process the uploaded file
#             filename = secure_filename(stego_image.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             stego_image.save(file_path)
            
#             # Use your existing decode_img_data function here
#             # For demonstration, we'll return a sample result
#             decoded_text = "This is a sample decoded message from the image steganography process."
            
#             log_activity(session['username'], "image_decode", filename, "success", f"Decoded text successfully")
#             return render_template('image_steganography.html', decoded_text=decoded_text)
    
#     return render_template('image_steganography.html')

@app.route('/image-steganography', methods=['GET', 'POST'])
@login_required
def image_steganography():
    if request.method == 'POST':
        operation = request.form.get('operation')

        if operation == 'encode':
            # --- validate inputs ---
            if 'cover_image' not in request.files:
                flash('No cover image provided', 'danger')
                return redirect(url_for('image_steganography'))

            cover_image = request.files['cover_image']
            text_data   = request.form.get('text_data')

            if cover_image.filename == '' or not text_data:
                flash('Missing required data', 'danger')
                return redirect(url_for('image_steganography'))

            # --- save uploaded cover image ---
            in_filename = secure_filename(cover_image.filename)
            in_path     = os.path.join(app.config['UPLOAD_FOLDER'], in_filename)
            cover_image.save(in_path)

            # --- prepare output path ---
            output_filename = f"stego_image_{datetime.datetime.now():%Y%m%d%H%M%S}.png"
            out_path        = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            # --- call backend stego function ---
            try:
                encode_image(in_path, text_data, out_path, session['username'])
                flash('Image encoding completed successfully', 'success')
                return redirect(url_for('download_file', filename=output_filename))
            except Exception as e:
                flash(f'Encoding failed: {e}', 'danger')
                log_activity(session['username'], 'image_encode', output_filename, 'failed', str(e))
                return redirect(url_for('image_steganography'))

        elif operation == 'decode':
            # --- validate inputs ---
            if 'stego_image' not in request.files:
                flash('No stego image provided', 'danger')
                return redirect(url_for('image_steganography'))

            stego_image = request.files['stego_image']
            if stego_image.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('image_steganography'))

            # --- save uploaded stego image ---
            filename  = secure_filename(stego_image.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            stego_image.save(file_path)

            # --- call backend decode function ---
            try:
                decoded_text = decode_image(file_path, session['username'])
                return render_template('image_steganography.html', decoded_text=decoded_text)
            except Exception as e:
                flash(f'Decoding failed: {e}', 'danger')
                log_activity(session['username'], 'image_decode', filename, 'failed', str(e))
                return redirect(url_for('image_steganography'))

    # GET
    return render_template('image_steganography.html')


# @app.route('/audio-steganography', methods=['GET', 'POST'])
# @login_required
# def audio_steganography():
#     if request.method == 'POST':
#         operation = request.form.get('operation')
        
#         if operation == 'encode':
#             if 'audio_file' not in request.files:
#                 flash('No audio file provided', 'danger')
#                 return redirect(url_for('audio_steganography'))
                
#             audio_file = request.files['audio_file']
#             text_data = request.form.get('text_data')
            
#             if audio_file.filename == '' or not text_data:
#                 flash('Missing required data', 'danger')
#                 return redirect(url_for('audio_steganography'))
                
#             # Save and process the uploaded file
#             filename = secure_filename(audio_file.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             audio_file.save(file_path)
            
#             # Use your existing encode_aud_data function here
#             # For demonstration, we'll create a sample output
#             output_filename = f"stego_audio_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.wav"
            
#             # Simulate encoding process
#             import shutil
#             shutil.copy(file_path, os.path.join(app.config['UPLOAD_FOLDER'], output_filename))
            
#             log_activity(session['username'], "audio_encode", output_filename, "success", f"Encoded {len(text_data)} characters")
#             flash('Audio encoding completed successfully', 'success')
#             return redirect(url_for('download_file', filename=output_filename))
            
#         elif operation == 'decode':
#             if 'stego_audio' not in request.files:
#                 flash('No stego audio provided', 'danger')
#                 return redirect(url_for('audio_steganography'))
                
#             stego_audio = request.files['stego_audio']
#             if stego_audio.filename == '':
#                 flash('No file selected', 'danger')
#                 return redirect(url_for('audio_steganography'))
                
#             # Save and process the uploaded file
#             filename = secure_filename(stego_audio.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             stego_audio.save(file_path)
            
#             # Use your existing decode_aud_data function here
#             # For demonstration, we'll return a sample result
#             decoded_text = "This is a sample decoded message from the audio steganography process."
            
#             log_activity(session['username'], "audio_decode", filename, "success", f"Decoded text successfully")
#             return render_template('audio_steganography.html', decoded_text=decoded_text)
    
#     return render_template('audio_steganography.html')


@app.route('/audio-steganography', methods=['GET', 'POST'])
@login_required
def audio_steganography():
    if request.method == 'POST':
        operation = request.form.get('operation')

        if operation == 'encode':
            # — validate inputs —
            if 'audio_file' not in request.files:
                flash('No audio file provided', 'danger')
                return redirect(url_for('audio_steganography'))

            audio_file = request.files['audio_file']
            text_data  = request.form.get('text_data')

            if audio_file.filename == '' or not text_data:
                flash('Missing required data', 'danger')
                return redirect(url_for('audio_steganography'))

            # — save uploaded audio —
            in_filename = secure_filename(audio_file.filename)
            in_path     = os.path.join(app.config['UPLOAD_FOLDER'], in_filename)
            audio_file.save(in_path)

            # — prepare output path —
            output_filename = f"stego_audio_{datetime.datetime.now():%Y%m%d%H%M%S}.wav"
            out_path        = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            # — call backend encode_audio —
            try:
                encode_audio(in_path, text_data, out_path, session['username'])
                flash('Audio encoding completed successfully', 'success')
                return redirect(url_for('download_file', filename=output_filename))
            except Exception as e:
                flash(f'Encoding failed: {e}', 'danger')
                log_activity(session['username'], 'audio_encode', output_filename, 'failed', str(e))
                return redirect(url_for('audio_steganography'))

        elif operation == 'decode':
            # — validate inputs —
            if 'stego_audio' not in request.files:
                flash('No stego audio provided', 'danger')
                return redirect(url_for('audio_steganography'))

            stego_audio = request.files['stego_audio']
            if stego_audio.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('audio_steganography'))

            # — save uploaded stego audio —
            filename  = secure_filename(stego_audio.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            stego_audio.save(file_path)

            # — call backend decode_audio —
            try:
                decoded_text = decode_audio(file_path, session['username'])
                return render_template('audio_steganography.html', decoded_text=decoded_text)
            except Exception as e:
                flash(f'Decoding failed: {e}', 'danger')
                log_activity(session['username'], 'audio_decode', filename, 'failed', str(e))
                return redirect(url_for('audio_steganography'))

    # GET
    return render_template('audio_steganography.html')


# @app.route('/video-steganography', methods=['GET', 'POST'])
# @login_required
# def video_steganography():
#     if request.method == 'POST':
#         operation = request.form.get('operation')
        
#         if operation == 'encode':
#             if 'video_file' not in request.files:
#                 flash('No video file provided', 'danger')
#                 return redirect(url_for('video_steganography'))
                
#             video_file = request.files['video_file']
#             text_data = request.form.get('text_data')
#             frame_number = request.form.get('frame_number')
#             encryption_key = request.form.get('encryption_key')
            
#             if video_file.filename == '' or not text_data or not frame_number or not encryption_key:
#                 flash('Missing required data', 'danger')
#                 return redirect(url_for('video_steganography'))
                
#             # Save and process the uploaded file
#             filename = secure_filename(video_file.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             video_file.save(file_path)
            
#             # Use your existing video encoding functions here
#             # For demonstration, we'll create a sample output
#             output_filename = f"stego_video_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.mp4"
            
#             # Simulate encoding process
#             import shutil
#             shutil.copy(file_path, os.path.join(app.config['UPLOAD_FOLDER'], output_filename))
            
#             log_activity(session['username'], "video_encode", output_filename, "success", 
#                         f"Encoded at frame {frame_number} with encryption")
#             flash('Video encoding completed successfully', 'success')
#             return redirect(url_for('download_file', filename=output_filename))
            
#         elif operation == 'decode':
#             if 'stego_video' not in request.files:
#                 flash('No stego video provided', 'danger')
#                 return redirect(url_for('video_steganography'))
                
#             stego_video = request.files['stego_video']
#             frame_number = request.form.get('frame_number')
#             decryption_key = request.form.get('decryption_key')
            
#             if stego_video.filename == '' or not frame_number or not decryption_key:
#                 flash('Missing required data', 'danger')
#                 return redirect(url_for('video_steganography'))
                
#             # Save and process the uploaded file
#             filename = secure_filename(stego_video.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             stego_video.save(file_path)
            
#             # Use your existing video decoding functions here
#             # For demonstration, we'll return a sample result
#             decoded_text = "This is a sample decoded and decrypted message from the video steganography process."
            
#             log_activity(session['username'], "video_decode", filename, "success", 
#                         f"Decoded from frame {frame_number} and decrypted")
#             return render_template('video_steganography.html', decoded_text=decoded_text)
    
#     return render_template('video_steganography.html')

@app.route('/video-steganography', methods=['GET', 'POST'])
@login_required
def video_steganography():
    if request.method == 'POST':
        operation = request.form.get('operation')

        if operation == 'encode':
            # — validate inputs —
            if 'video_file' not in request.files:
                flash('No video file provided', 'danger')
                return redirect(url_for('video_steganography'))

            video_file    = request.files['video_file']
            text_data     = request.form.get('text_data')
            frame_number  = request.form.get('frame_number')
            encryption_key= request.form.get('encryption_key')

            if (video_file.filename == '' or
                not text_data or
                not frame_number or
                not encryption_key):
                flash('Missing required data', 'danger')
                return redirect(url_for('video_steganography'))

            # — save uploaded video —
            in_filename = secure_filename(video_file.filename)
            in_path     = os.path.join(app.config['UPLOAD_FOLDER'], in_filename)
            video_file.save(in_path)

            # — prepare output path —
            output_filename = f"stego_video_{datetime.datetime.now():%Y%m%d%H%M%S}.mp4"
            out_path        = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            # — call backend encode_video —
            try:
                fn = int(frame_number)
                encode_video(
                    input_path=in_path,
                    data=text_data,
                    frame_no=fn,
                    output_path=out_path,
                    username=session['username'],
                    key=encryption_key
                )
                flash('Video encoding completed successfully', 'success')
                return redirect(url_for('download_file', filename=output_filename))
            except Exception as e:
                flash(f'Encoding failed: {e}', 'danger')
                log_activity(
                    session['username'],
                    'video_encode',
                    output_filename,
                    'failed',
                    str(e)
                )
                return redirect(url_for('video_steganography'))

        elif operation == 'decode':
            # — validate inputs —
            if 'stego_video' not in request.files:
                flash('No stego video provided', 'danger')
                return redirect(url_for('video_steganography'))

            stego_video   = request.files['stego_video']
            frame_number  = request.form.get('frame_number')
            decryption_key= request.form.get('decryption_key')

            if (stego_video.filename == '' or
                not frame_number or
                not decryption_key):
                flash('Missing required data', 'danger')
                return redirect(url_for('video_steganography'))

            # — save uploaded stego video —
            filename  = secure_filename(stego_video.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            stego_video.save(file_path)

            # — call backend decode_video —
            try:
                fn = int(frame_number)
                decoded_text = decode_video(
                    input_path=file_path,
                    frame_no=fn,
                    username=session['username'],
                    key=decryption_key
                )
                return render_template(
                    'video_steganography.html',
                    decoded_text=decoded_text
                )
            except Exception as e:
                flash(f'Decoding failed: {e}', 'danger')
                log_activity(
                    session['username'],
                    'video_decode',
                    filename,
                    'failed',
                    str(e)
                )
                return redirect(url_for('video_steganography'))

    # GET
    return render_template('video_steganography.html')


@app.route('/logs')
@login_required
def logs():
    if not os.path.exists('steganography_logs.json'):
        flash('No logs available', 'info')
        return render_template('logs.html', logs=[])
    
    with open('steganography_logs.json', 'r') as f:
        all_logs = json.load(f)
    
    # Filter logs based on user role
    if session['role'] == 'admin':
        user_logs = all_logs
    else:
        user_logs = [log for log in all_logs if log['username'] == session['username']]
    
    return render_template('logs.html', logs=user_logs)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users_list = []
    for username, data in USERS.items():
        last_login = data['last_login'] if data['last_login'] else 'Never'
        users_list.append({
            'username': username,
            'role': data['role'],
            'last_login': last_login
        })
    
    return render_template('admin_users.html', users=users_list)

@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_user():
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        role = request.form.get('role')
        
        if new_username in USERS:
            flash('User already exists', 'danger')
            return redirect(url_for('admin_add_user'))
            
        if role not in ['admin', 'user']:
            flash('Invalid role', 'danger')
            return redirect(url_for('admin_add_user'))
            
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('admin_add_user'))
            
        USERS[new_username] = {
            'password_hash': hash_password(new_password),
            'role': role,
            'last_login': None
        }
        
        flash(f'User {new_username} created successfully', 'success')
        log_activity(session['username'], "user_create", new_username, "success")
        return redirect(url_for('admin_users'))
    
    return render_template('admin_add_user.html')

@app.route('/admin/delete-user/<username>')
@login_required
@admin_required
def admin_delete_user(username):
    if username == session['username']:
        flash('Cannot delete your own account', 'danger')
    elif username in USERS:
        del USERS[username]
        flash(f'User {username} deleted successfully', 'success')
        log_activity(session['username'], "user_delete", username, "success")
    else:
        flash('User not found', 'danger')
    
    return redirect(url_for('admin_users'))

# @app.route('/admin/reset-password/<username>', methods=['GET', 'POST'])
# @login_required
# @admin_required
# def admin_reset_password(username):
#     if username not in USERS:
#         flash('User not found', 'danger')
#         return redirect(url_for('admin_users'))
    
#     if request.method == 'POST':
#         new_password = request.form.get('new_password')
        
#         if len(new_password) < 8:
#             flash('Password must be at least 8 characters long', 'danger')
#         else:
#             USERS[username]['password_hash'] = hash_password(new_password)
#             flash(f'Password for {username} reset successfully', 'success')
#             log_activity(session['username'], "password_reset", username, "success")
#             return redirect(url_for('admin_users'))

@app.route('/admin/reset-password/<username>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_reset_password(username):
    if username not in USERS:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
        else:
            USERS[username]['password_hash'] = hash_password(new_password)
            flash(f'Password for {username} reset successfully', 'success')
            log_activity(session['username'], "password_reset", username, "success")
            return redirect(url_for('admin_users'))
    
    return render_template('admin_reset_password.html', username=username)

        
# @app.route('/logs')
# @login_required
# def logs():
#     if not os.path.exists('steganography_logs.json'):
#         flash('No logs available', 'info')
#         return render_template('logs.html', logs=[])
    
#     with open('steganography_logs.json', 'r') as f:
#         all_logs = json.load(f)
    
#     # Filter logs based on user role
#     if session['role'] == 'admin':
#         user_logs = all_logs
#     else:
#         user_logs = [log for log in all_logs if log['username'] == session['username']]
    
#     return render_template('logs.html', logs=user_logs)
#     return render_template('admin_reset_password.html', username=username)

# @app.route('/logs')
# @login_required
# def logs():
#     if not os.path.exists('steganography_logs.json'):
#         flash('No logs available', 'info')
#         return render_template('logs.html', logs=[])
    
#     with open('steganography_logs.json', 'r') as f:
#         all_logs = json.load(f)
    
#     # Filter logs based on user role
#     if session['role'] == 'admin':
#         user_logs = all_logs
#     else:
#         user_logs = [log for log in all_logs if log['username'] == session['username']]
    
#     return render_template('logs.html', logs=user_logs)


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    log_activity("system", "server_error", "application", "failed", str(e))
    return render_template('500.html'), 500
@app.context_processor
def inject_now():
    return {'now': datetime.datetime.now()}


if __name__ == '__main__':
    # In production, use proper WSGI server and enable HTTPS
    app.run(debug=False, ssl_context='adhoc')  # 'adhoc' creates a self-signed cert for testing