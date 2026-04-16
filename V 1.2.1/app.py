import os
import secrets
import io
import shutil
import threading
import time as _time
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from openpyxl import Workbook

from database import get_db, init_db, DB_PATH

def _hash_pw(password):
    return generate_password_hash(password, method='pbkdf2:sha256')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
BACKUP_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
os.makedirs(BACKUP_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def log_activity(user_id, action, details=''):
    db = get_db()
    db.execute('INSERT INTO activity_logs (user_id, action, ip_address, details) VALUES (?, ?, ?, ?)',
               (user_id, action, request.remote_addr if request else '', details))
    db.commit()
    db.close()


def send_notification(user_id, title, message, notif_type='info', link=None):
    db = get_db()
    db.execute('INSERT INTO notifications (user_id, title, message, type, link) VALUES (?, ?, ?, ?, ?)',
               (user_id, title, message, notif_type, link))
    db.commit()
    db.close()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ── User Model ───────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, username, password_hash, full_name, email, phone, pin_hash, profile_pic, role, is_active, created_at):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.full_name = full_name
        self.email = email
        self.phone = phone
        self.pin_hash = pin_hash
        self.profile_pic = profile_pic
        self.role = role
        self._is_active = is_active
        self.created_at = created_at

    @property
    def is_active(self):
        return bool(self._is_active)

    def is_super_admin(self):
        return self.role == 'super_admin'

    def is_admin(self):
        return self.role in ('super_admin', 'admin')

    def has_pin(self):
        return bool(self.pin_hash)


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    if row:
        return User(**dict(row))
    return None


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin():
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


def super_admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_super_admin():
            flash('Access denied. Super Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def inject_notification_count():
    if current_user.is_authenticated:
        db = get_db()
        count = db.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0',
                          (current_user.id,)).fetchone()[0]
        msg_count = db.execute('SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0',
                              (current_user.id,)).fetchone()[0]
        db.close()
        return {'unread_notif_count': count, 'unread_msg_count': msg_count}
    return {'unread_notif_count': 0, 'unread_msg_count': 0}


# ── Auth Routes ──────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        row = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()

        if row and check_password_hash(row['password_hash'], password):
            user = User(**dict(row))
            if not user.is_active:
                flash('Your account has been deactivated. Contact admin.', 'danger')
                return render_template('login.html')
            login_user(user)
            # Log the login
            log_activity(user.id, 'login', 'User logged in')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout', 'User logged out')
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


# ── PIN Management ───────────────────────────────────────────
@app.route('/pin/setup', methods=['GET', 'POST'])
@login_required
def setup_pin():
    if request.method == 'POST':
        pin = request.form.get('pin', '').strip()
        confirm_pin = request.form.get('confirm_pin', '').strip()

        if not pin or len(pin) < 4 or len(pin) > 6 or not pin.isdigit():
            flash('PIN must be 4-6 digits.', 'danger')
        elif pin != confirm_pin:
            flash('PINs do not match.', 'danger')
        else:
            db = get_db()
            db.execute('UPDATE users SET pin_hash = ? WHERE id = ?',
                      (_hash_pw(pin), current_user.id))
            db.commit()
            db.close()
            log_activity(current_user.id, 'pin_setup', 'User set up PIN')
            flash('PIN set successfully.', 'success')
            return redirect(url_for('dashboard'))

    return render_template('pin_setup.html')


@app.route('/pin/verify', methods=['POST'])
@login_required
def verify_pin():
    pin = request.form.get('pin', '').strip()
    db = get_db()
    row = db.execute('SELECT pin_hash FROM users WHERE id = ?', (current_user.id,)).fetchone()
    db.close()

    if not row or not row['pin_hash']:
        return jsonify({'valid': False, 'error': 'PIN not set. Please set up your PIN first.'})

    if check_password_hash(row['pin_hash'], pin):
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False, 'error': 'Invalid PIN. Please try again.'})


# ── Notifications ────────────────────────────────────────────
@app.route('/notifications')
@login_required
def notifications():
    db = get_db()
    notifs = db.execute('''
        SELECT * FROM notifications WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 100
    ''', (current_user.id,)).fetchall()
    # Mark all as read
    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0',
               (current_user.id,))
    db.commit()
    db.close()
    return render_template('notifications.html', notifications=notifs)


@app.route('/notifications/poll')
@login_required
def notifications_poll():
    after_id = request.args.get('after', 0, type=int)
    db = get_db()
    count = db.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0',
                       (current_user.id,)).fetchone()[0]
    msg_count = db.execute('SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0',
                           (current_user.id,)).fetchone()[0]
    new_notifs = []
    if after_id:
        rows = db.execute('''
            SELECT id, title, message, type, link, created_at FROM notifications
            WHERE user_id = ? AND id > ? ORDER BY id ASC LIMIT 10
        ''', (current_user.id, after_id)).fetchall()
        new_notifs = [dict(r) for r in rows]
    else:
        latest = db.execute('SELECT MAX(id) FROM notifications WHERE user_id = ?',
                            (current_user.id,)).fetchone()[0]
        new_notifs = [{'id': latest or 0}]
    db.close()
    return jsonify({'notif_count': count, 'msg_count': msg_count, 'notifications': new_notifs})


@app.route('/tasks/remind/<int:task_id>')
@login_required
def send_task_reminder(task_id):
    db = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    db.close()

    if not task:
        flash('Task not found.', 'danger')
        return redirect(url_for('tasks'))

    if not task['assigned_to']:
        flash('This task is not assigned to anyone.', 'warning')
        return redirect(url_for('tasks'))

    if task['status'] == 'completed':
        flash('This task is already completed.', 'info')
        return redirect(url_for('tasks'))

    send_notification(
        task['assigned_to'],
        'Urgent Task Reminder',
        f'{current_user.full_name} sent you a reminder: Please complete the task "{task["title"]}" — it\'s urgent!',
        'reminder',
        url_for('tasks')
    )
    log_activity(current_user.id, 'task_reminder', f'Sent reminder for task #{task_id}: {task["title"]}')
    flash(f'Reminder sent for task "{task["title"]}".', 'success')
    return redirect(url_for('tasks'))


@app.route('/tasks/accept/<int:task_id>')
@login_required
def accept_task(task_id):
    db = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()

    if not task or task['assigned_to'] != current_user.id:
        db.close()
        flash('Task not found or not assigned to you.', 'danger')
        return redirect(url_for('tasks'))

    if task['status'] != 'pending':
        db.close()
        flash('Task has already been accepted.', 'info')
        return redirect(url_for('tasks'))

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    db.execute('UPDATE tasks SET status = ?, accepted_at = ? WHERE id = ?',
               ('accepted', now, task_id))
    db.commit()
    db.close()

    # Notify the task creator
    send_notification(
        task['created_by'],
        'Task Accepted',
        f'{current_user.full_name} accepted the task: "{task["title"]}"',
        'task_accepted',
        url_for('tasks')
    )
    log_activity(current_user.id, 'accept_task', f'Accepted task #{task_id}: {task["title"]}')
    flash(f'Task "{task["title"]}" accepted.', 'success')
    return redirect(url_for('tasks'))


@app.route('/tasks/start/<int:task_id>')
@login_required
def start_task(task_id):
    db = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()

    if not task or task['assigned_to'] != current_user.id:
        db.close()
        flash('Task not found or not assigned to you.', 'danger')
        return redirect(url_for('tasks'))

    if task['status'] not in ('pending', 'accepted'):
        db.close()
        flash('Task cannot be started from its current status.', 'info')
        return redirect(url_for('tasks'))

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    accepted_at = task['accepted_at'] or now
    db.execute('UPDATE tasks SET status = ?, accepted_at = ?, started_at = ? WHERE id = ?',
               ('in_progress', accepted_at, now, task_id))
    db.commit()
    db.close()

    # Notify the task creator
    send_notification(
        task['created_by'],
        'Task Started',
        f'{current_user.full_name} started working on the task: "{task["title"]}"',
        'task_started',
        url_for('tasks')
    )
    log_activity(current_user.id, 'start_task', f'Started task #{task_id}: {task["title"]}')
    flash(f'Task "{task["title"]}" started.', 'success')
    return redirect(url_for('tasks'))


# ── Profile Picture ──────────────────────────────────────────
@app.route('/profile/upload-pic/<int:user_id>', methods=['POST'])
@login_required
def upload_profile_pic(user_id):
    # Users can upload their own pic; admins can upload for any user
    if user_id != current_user.id and not current_user.is_super_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    if 'profile_pic' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    file = request.files['profile_pic']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    if file and allowed_file(file.filename):
        ext = secure_filename(file.filename).rsplit('.', 1)[1].lower()
        filename = f'profile_{user_id}.{ext}'
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        db = get_db()
        db.execute('UPDATE users SET profile_pic = ? WHERE id = ?', (filename, user_id))
        db.commit()
        db.close()
        log_activity(current_user.id, 'upload_profile_pic', f'Updated profile picture for user #{user_id}')
        flash('Profile picture updated.', 'success')
    else:
        flash('Invalid file type. Use PNG, JPG, GIF or WEBP.', 'danger')

    return redirect(request.referrer or url_for('dashboard'))


# ── Dashboard ────────────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    db = get_db()

    # Task stats
    if current_user.is_admin():
        total_tasks = db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]
        pending_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE status='pending'").fetchone()[0]
        in_progress_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE status='in_progress'").fetchone()[0]
        completed_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE status='completed'").fetchone()[0]
    else:
        total_tasks = db.execute('SELECT COUNT(*) FROM tasks WHERE assigned_to = ?', (current_user.id,)).fetchone()[0]
        pending_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND status='pending'", (current_user.id,)).fetchone()[0]
        in_progress_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND status='in_progress'", (current_user.id,)).fetchone()[0]
        completed_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND status='completed'", (current_user.id,)).fetchone()[0]

    # Delivery stats
    total_deliveries = db.execute('SELECT COUNT(*) FROM deliveries').fetchone()[0]
    pending_payments = db.execute("SELECT COUNT(*) FROM deliveries WHERE charge_paid = 0 AND transportation_charge > 0").fetchone()[0]
    pending_notes = db.execute("SELECT COUNT(*) FROM deliveries WHERE signed_note_status = 'pending'").fetchone()[0]

    # Recent tasks
    if current_user.is_admin():
        recent_tasks = db.execute('''
            SELECT t.*, u.full_name as assigned_name, c.full_name as creator_name
            FROM tasks t
            LEFT JOIN users u ON t.assigned_to = u.id
            LEFT JOIN users c ON t.created_by = c.id
            ORDER BY t.created_at DESC LIMIT 5
        ''').fetchall()
    else:
        recent_tasks = db.execute('''
            SELECT t.*, u.full_name as assigned_name, c.full_name as creator_name
            FROM tasks t
            LEFT JOIN users u ON t.assigned_to = u.id
            LEFT JOIN users c ON t.created_by = c.id
            WHERE t.assigned_to = ?
            ORDER BY t.created_at DESC LIMIT 5
        ''', (current_user.id,)).fetchall()

    # Recent deliveries
    recent_deliveries = db.execute('''
        SELECT d.*, u.full_name as creator_name
        FROM deliveries d
        LEFT JOIN users u ON d.created_by = u.id
        ORDER BY d.created_at DESC LIMIT 5
    ''').fetchall()

    db.close()

    return render_template('dashboard.html',
        total_tasks=total_tasks, pending_tasks=pending_tasks,
        in_progress_tasks=in_progress_tasks, completed_tasks=completed_tasks,
        total_deliveries=total_deliveries, pending_payments=pending_payments,
        pending_notes=pending_notes, recent_tasks=recent_tasks,
        recent_deliveries=recent_deliveries)


# ── Task Management ──────────────────────────────────────────
@app.route('/tasks')
@login_required
def tasks():
    db = get_db()
    status_filter = request.args.get('status', '')
    user_filter = request.args.get('user', '')
    priority_filter = request.args.get('priority', '')
    group_filter = request.args.get('group', '')

    query = '''
        SELECT t.*, u.full_name as assigned_name, u.phone as assigned_phone, c.full_name as creator_name,
               g.name as group_name, g.color as group_color
        FROM tasks t
        LEFT JOIN users u ON t.assigned_to = u.id
        LEFT JOIN users c ON t.created_by = c.id
        LEFT JOIN task_groups g ON t.group_id = g.id
        WHERE 1=1
    '''
    params = []

    if not current_user.is_admin():
        query += ' AND t.assigned_to = ?'
        params.append(current_user.id)

    if status_filter:
        query += ' AND t.status = ?'
        params.append(status_filter)

    if priority_filter:
        query += ' AND t.priority = ?'
        params.append(priority_filter)

    if user_filter and current_user.is_admin():
        query += ' AND t.assigned_to = ?'
        params.append(int(user_filter))

    if group_filter:
        query += ' AND t.group_id = ?'
        params.append(int(group_filter))

    query += ' ORDER BY t.created_at DESC'

    task_list = db.execute(query, params).fetchall()
    users = db.execute("SELECT id, full_name FROM users WHERE is_active = 1").fetchall()
    groups = db.execute("SELECT id, name, color FROM task_groups ORDER BY name").fetchall()
    db.close()

    return render_template('tasks.html', tasks=task_list, users=users, groups=groups,
                           status_filter=status_filter, user_filter=user_filter,
                           priority_filter=priority_filter, group_filter=group_filter)


@app.route('/tasks/add', methods=['GET', 'POST'])
@login_required
def add_task():
    db = get_db()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        assigned_to = request.form.get('assigned_to')
        priority = request.form.get('priority', 'medium')
        group_id = request.form.get('group_id')

        if not title:
            flash('Task title is required.', 'danger')
        else:
            db.execute('''
                INSERT INTO tasks (title, description, assigned_to, created_by, priority, group_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (title, description, int(assigned_to) if assigned_to else None, current_user.id, priority,
                  int(group_id) if group_id else None))
            db.commit()
            log_activity(current_user.id, 'add_task', f'Added task: {title}')

            # Send notification to assigned person
            if assigned_to:
                send_notification(
                    int(assigned_to),
                    'New Task Assigned',
                    f'{current_user.full_name} assigned you a new task: "{title}" (Priority: {priority.title()})',
                    'task_assigned',
                    url_for('tasks')
                )

            db.close()
            flash('Task added successfully.', 'success')
            return redirect(url_for('tasks'))

    users = db.execute("SELECT id, full_name FROM users WHERE is_active = 1").fetchall()
    groups = db.execute("SELECT id, name, color FROM task_groups ORDER BY name").fetchall()
    db.close()
    return render_template('task_form.html', task=None, users=users, groups=groups)


@app.route('/tasks/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    db = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()

    if not task:
        db.close()
        flash('Task not found.', 'danger')
        return redirect(url_for('tasks'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        assigned_to = request.form.get('assigned_to')
        priority = request.form.get('priority', 'medium')
        status = request.form.get('status', 'pending')
        group_id = request.form.get('group_id')

        completed_at = None
        if status == 'completed' and task['status'] != 'completed':
            completed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        elif status == 'completed' and task['completed_at']:
            completed_at = task['completed_at']

        accepted_at = task['accepted_at']
        started_at = task['started_at']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if status in ('accepted', 'in_progress', 'completed') and not accepted_at:
            accepted_at = now
        if status in ('in_progress', 'completed') and not started_at:
            started_at = now

        if not title:
            flash('Task title is required.', 'danger')
        else:
            db.execute('''
                UPDATE tasks SET title=?, description=?, assigned_to=?, priority=?, status=?, accepted_at=?, started_at=?, completed_at=?, group_id=?
                WHERE id=?
            ''', (title, description, int(assigned_to) if assigned_to else None,
                  priority, status, accepted_at, started_at, completed_at,
                  int(group_id) if group_id else None, task_id))
            db.commit()
            log_activity(current_user.id, 'edit_task', f'Edited task #{task_id}: {title} [Status: {status}]')

            # Notify if assigned person changed
            new_assigned = int(assigned_to) if assigned_to else None
            old_assigned = task['assigned_to']
            if new_assigned and new_assigned != old_assigned:
                send_notification(
                    new_assigned,
                    'Task Reassigned to You',
                    f'{current_user.full_name} assigned you a task: "{title}" (Priority: {priority.title()})',
                    'task_assigned',
                    url_for('tasks')
                )

            db.close()
            flash('Task updated successfully.', 'success')
            return redirect(url_for('tasks'))

    users = db.execute("SELECT id, full_name FROM users WHERE is_active = 1").fetchall()
    groups = db.execute("SELECT id, name, color FROM task_groups ORDER BY name").fetchall()
    db.close()
    return render_template('task_form.html', task=task, users=users, groups=groups)


@app.route('/tasks/delete/<int:task_id>')
@admin_required
def delete_task(task_id):
    db = get_db()
    task = db.execute('SELECT title FROM tasks WHERE id = ?', (task_id,)).fetchone()
    db.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    db.commit()
    log_activity(current_user.id, 'delete_task', f'Deleted task #{task_id}: {task["title"] if task else "Unknown"}')
    db.close()
    flash('Task deleted.', 'success')
    return redirect(url_for('tasks'))


@app.route('/tasks/export')
@login_required
def export_tasks():
    db = get_db()
    status_filter = request.args.get('status', '')
    user_filter = request.args.get('user', '')
    priority_filter = request.args.get('priority', '')

    query = '''
        SELECT t.*, u.full_name as assigned_name, c.full_name as creator_name, g.name as group_name
        FROM tasks t
        LEFT JOIN users u ON t.assigned_to = u.id
        LEFT JOIN users c ON t.created_by = c.id
        LEFT JOIN task_groups g ON t.group_id = g.id
        WHERE 1=1
    '''
    params = []
    if not current_user.is_admin():
        query += ' AND t.assigned_to = ?'
        params.append(current_user.id)
    if status_filter:
        query += ' AND t.status = ?'
        params.append(status_filter)
    if priority_filter:
        query += ' AND t.priority = ?'
        params.append(priority_filter)
    if user_filter and current_user.is_admin():
        query += ' AND t.assigned_to = ?'
        params.append(int(user_filter))
    query += ' ORDER BY t.created_at DESC'

    task_list = db.execute(query, params).fetchall()
    db.close()

    wb = Workbook()
    ws = wb.active
    ws.title = 'Tasks'
    ws.append(['#', 'Title', 'Group', 'Description', 'Assigned To', 'Created By', 'Priority', 'Status',
               'Created', 'Accepted', 'Started', 'Completed'])
    for t in task_list:
        ws.append([t['id'], t['title'], t['group_name'] or '', t['description'] or '', t['assigned_name'] or 'Unassigned',
                   t['creator_name'], t['priority'], t['status'],
                   t['created_at'] or '', t['accepted_at'] or '', t['started_at'] or '', t['completed_at'] or ''])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return send_file(output, download_name='tasks.xlsx', as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# ── Task Groups ──────────────────────────────────────────────
@app.route('/task-groups')
@admin_required
def task_groups():
    db = get_db()
    groups = db.execute('''
        SELECT g.*, u.full_name as creator_name,
               (SELECT COUNT(*) FROM tasks WHERE group_id = g.id) as task_count
        FROM task_groups g
        LEFT JOIN users u ON g.created_by = u.id
        ORDER BY g.name
    ''').fetchall()
    db.close()
    return render_template('task_groups.html', groups=groups)


@app.route('/task-groups/add', methods=['POST'])
@admin_required
def add_task_group():
    name = request.form.get('name', '').strip()
    color = request.form.get('color', '#6c757d').strip()
    if not name:
        flash('Group name is required.', 'danger')
        return redirect(url_for('task_groups'))
    db = get_db()
    existing = db.execute('SELECT id FROM task_groups WHERE name = ?', (name,)).fetchone()
    if existing:
        flash('A group with that name already exists.', 'warning')
        db.close()
        return redirect(url_for('task_groups'))
    db.execute('INSERT INTO task_groups (name, color, created_by) VALUES (?, ?, ?)',
               (name, color, current_user.id))
    db.commit()
    log_activity(current_user.id, 'add_task_group', f'Created task group: {name}')
    db.close()
    flash(f'Group "{name}" created.', 'success')
    return redirect(url_for('task_groups'))


@app.route('/task-groups/edit/<int:group_id>', methods=['POST'])
@admin_required
def edit_task_group(group_id):
    name = request.form.get('name', '').strip()
    color = request.form.get('color', '#6c757d').strip()
    if not name:
        flash('Group name is required.', 'danger')
        return redirect(url_for('task_groups'))
    db = get_db()
    existing = db.execute('SELECT id FROM task_groups WHERE name = ? AND id != ?', (name, group_id)).fetchone()
    if existing:
        flash('A group with that name already exists.', 'warning')
        db.close()
        return redirect(url_for('task_groups'))
    db.execute('UPDATE task_groups SET name = ?, color = ? WHERE id = ?', (name, color, group_id))
    db.commit()
    log_activity(current_user.id, 'edit_task_group', f'Updated task group #{group_id}: {name}')
    db.close()
    flash(f'Group "{name}" updated.', 'success')
    return redirect(url_for('task_groups'))


@app.route('/task-groups/delete/<int:group_id>')
@admin_required
def delete_task_group(group_id):
    db = get_db()
    group = db.execute('SELECT name FROM task_groups WHERE id = ?', (group_id,)).fetchone()
    db.execute('DELETE FROM task_groups WHERE id = ?', (group_id,))
    db.commit()
    log_activity(current_user.id, 'delete_task_group', f'Deleted task group #{group_id}: {group["name"] if group else "Unknown"}')
    db.close()
    flash('Task group deleted.', 'success')
    return redirect(url_for('task_groups'))


# ── Delivery Tracking ────────────────────────────────────────
@app.route('/deliveries')
@login_required
def deliveries():
    db = get_db()
    payment_filter = request.args.get('payment', '')
    note_filter = request.args.get('note_status', '')
    dn_search = request.args.get('dn_search', '').strip()
    driver_filter = request.args.get('driver', '')

    query = '''
        SELECT d.*, u.full_name as creator_name, dp.name as driver_name, dp.vehicle_no as driver_vehicle, dp.mobile as driver_mobile
        FROM deliveries d
        LEFT JOIN users u ON d.created_by = u.id
        LEFT JOIN delivery_persons dp ON d.delivery_person_id = dp.id
        WHERE 1=1
    '''
    params = []

    if dn_search:
        query += ' AND d.delivery_note_number LIKE ?'
        params.append(f'%{dn_search}%')

    if driver_filter:
        query += ' AND d.delivery_person_id = ?'
        params.append(int(driver_filter))

    if payment_filter == 'paid':
        query += ' AND d.charge_paid = 1'
    elif payment_filter == 'unpaid':
        query += ' AND d.charge_paid = 0 AND d.transportation_charge > 0'

    if note_filter:
        query += ' AND d.signed_note_status = ?'
        params.append(note_filter)

    query += ' ORDER BY d.created_at DESC'

    delivery_list = db.execute(query, params).fetchall()
    drivers = db.execute("SELECT id, name FROM delivery_persons WHERE is_active = 1 ORDER BY name").fetchall()
    db.close()

    return render_template('deliveries.html', deliveries=delivery_list,
                           payment_filter=payment_filter, note_filter=note_filter,
                           dn_search=dn_search, driver_filter=driver_filter, drivers=drivers)


@app.route('/deliveries/add', methods=['GET', 'POST'])
@login_required
def add_delivery():
    if request.method == 'POST':
        delivery_note_number = request.form.get('delivery_note_number', '').strip()
        description = request.form.get('description', '').strip()
        customer_name = request.form.get('customer_name', '').strip()
        delivery_date = request.form.get('delivery_date') or None
        delivery_person_id = request.form.get('delivery_person_id') or None
        transportation_charge = float(request.form.get('transportation_charge') or 0)
        charge_paid = 1 if request.form.get('charge_paid') else 0
        paid_date = request.form.get('paid_date') or None
        paid_by = request.form.get('paid_by', '').strip()
        payment_method = request.form.get('payment_method', '')
        narration = request.form.get('narration', '').strip()
        signed_note_status = request.form.get('signed_note_status', 'pending')

        if not delivery_note_number or not customer_name:
            flash('Delivery note number and customer name are required.', 'danger')
            db = get_db()
            persons = db.execute("SELECT * FROM delivery_persons WHERE is_active = 1 ORDER BY name").fetchall()
            users_list = db.execute("SELECT id, full_name FROM users WHERE is_active = 1").fetchall()
            db.close()
            return render_template('delivery_form.html', delivery=None, persons=persons, users=users_list)

        db = get_db()
        db.execute('''
            INSERT INTO deliveries (delivery_note_number, description, customer_name,
                delivery_date, delivery_person_id, transportation_charge, charge_paid, paid_date, paid_by,
                payment_method, narration, signed_note_status, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (delivery_note_number, description, customer_name, delivery_date,
              int(delivery_person_id) if delivery_person_id else None,
              transportation_charge, charge_paid, paid_date, paid_by,
              payment_method, narration, signed_note_status, current_user.id))
        db.commit()
        log_activity(current_user.id, 'add_delivery', f'Added delivery: {delivery_note_number} - {customer_name}')
        db.close()
        flash('Delivery added successfully.', 'success')
        return redirect(url_for('deliveries'))

    db = get_db()
    persons = db.execute("SELECT * FROM delivery_persons WHERE is_active = 1 ORDER BY name").fetchall()
    users_list = db.execute("SELECT id, full_name FROM users WHERE is_active = 1").fetchall()
    db.close()
    return render_template('delivery_form.html', delivery=None, persons=persons, users=users_list)


@app.route('/deliveries/edit/<int:delivery_id>', methods=['GET', 'POST'])
@login_required
def edit_delivery(delivery_id):
    db = get_db()
    delivery = db.execute('SELECT * FROM deliveries WHERE id = ?', (delivery_id,)).fetchone()

    if not delivery:
        db.close()
        flash('Delivery not found.', 'danger')
        return redirect(url_for('deliveries'))

    if request.method == 'POST':
        delivery_note_number = request.form.get('delivery_note_number', '').strip()
        description = request.form.get('description', '').strip()
        customer_name = request.form.get('customer_name', '').strip()
        delivery_date = request.form.get('delivery_date') or None
        delivery_person_id = request.form.get('delivery_person_id') or None
        transportation_charge = float(request.form.get('transportation_charge') or 0)
        charge_paid = 1 if request.form.get('charge_paid') else 0
        paid_date = request.form.get('paid_date') or None
        paid_by = request.form.get('paid_by', '').strip()
        payment_method = request.form.get('payment_method', '')
        narration = request.form.get('narration', '').strip()
        signed_note_status = request.form.get('signed_note_status', 'pending')

        # Auto-fill payment details when marking as paid
        if charge_paid and not delivery['charge_paid']:
            if not paid_date:
                paid_date = datetime.now().strftime('%Y-%m-%d')
            if not paid_by:
                paid_by = current_user.full_name

        # Require payment details when marking as paid
        if charge_paid and transportation_charge > 0:
            if not payment_method:
                flash('Payment method is required when marking charge as paid.', 'danger')
                persons = db.execute("SELECT * FROM delivery_persons WHERE is_active = 1 ORDER BY name").fetchall()
                users_list = db.execute("SELECT id, full_name FROM users WHERE is_active = 1").fetchall()
                db.close()
                return render_template('delivery_form.html', delivery=delivery, persons=persons, users=users_list)

        if not delivery_note_number or not customer_name:
            flash('Delivery note number and customer name are required.', 'danger')
        else:
            db.execute('''
                UPDATE deliveries SET delivery_note_number=?, description=?, customer_name=?,
                    delivery_date=?, delivery_person_id=?, transportation_charge=?, charge_paid=?, paid_date=?,
                    paid_by=?, payment_method=?, narration=?, signed_note_status=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=?
            ''', (delivery_note_number, description, customer_name, delivery_date,
                  int(delivery_person_id) if delivery_person_id else None,
                  transportation_charge, charge_paid, paid_date, paid_by,
                  payment_method, narration, signed_note_status, delivery_id))
            db.commit()
            log_activity(current_user.id, 'edit_delivery', f'Edited delivery #{delivery_id}: {delivery_note_number} - {customer_name}')
            db.close()
            flash('Delivery updated successfully.', 'success')
            return redirect(url_for('deliveries'))

    persons = db.execute("SELECT * FROM delivery_persons WHERE is_active = 1 ORDER BY name").fetchall()
    users_list = db.execute("SELECT id, full_name FROM users WHERE is_active = 1").fetchall()
    db.close()
    return render_template('delivery_form.html', delivery=delivery, persons=persons, users=users_list)


@app.route('/deliveries/delete/<int:delivery_id>')
@admin_required
def delete_delivery(delivery_id):
    db = get_db()
    delivery = db.execute('SELECT delivery_note_number, customer_name FROM deliveries WHERE id = ?', (delivery_id,)).fetchone()
    db.execute('DELETE FROM deliveries WHERE id = ?', (delivery_id,))
    db.commit()
    log_activity(current_user.id, 'delete_delivery', f'Deleted delivery #{delivery_id}: {delivery["delivery_note_number"] + " - " + delivery["customer_name"] if delivery else "Unknown"}')
    db.close()
    flash('Delivery deleted.', 'success')
    return redirect(url_for('deliveries'))


@app.route('/deliveries/export')
@login_required
def export_deliveries():
    db = get_db()
    payment_filter = request.args.get('payment', '')
    note_filter = request.args.get('note_status', '')
    dn_search = request.args.get('dn_search', '').strip()
    driver_filter = request.args.get('driver', '')

    query = '''
        SELECT d.*, u.full_name as creator_name, dp.name as driver_name, dp.vehicle_no as driver_vehicle
        FROM deliveries d
        LEFT JOIN users u ON d.created_by = u.id
        LEFT JOIN delivery_persons dp ON d.delivery_person_id = dp.id
        WHERE 1=1
    '''
    params = []
    if dn_search:
        query += ' AND d.delivery_note_number LIKE ?'
        params.append(f'%{dn_search}%')
    if driver_filter:
        query += ' AND d.delivery_person_id = ?'
        params.append(int(driver_filter))
    if payment_filter == 'paid':
        query += ' AND d.charge_paid = 1'
    elif payment_filter == 'unpaid':
        query += ' AND d.charge_paid = 0 AND d.transportation_charge > 0'
    if note_filter:
        query += ' AND d.signed_note_status = ?'
        params.append(note_filter)
    query += ' ORDER BY d.created_at DESC'

    delivery_list = db.execute(query, params).fetchall()
    db.close()

    wb = Workbook()
    ws = wb.active
    ws.title = 'Deliveries'
    ws.append(['Note #', 'Customer', 'Description', 'Driver', 'Vehicle', 'Delivery Date',
               'Transport Charge', 'Payment Status', 'Payment Method', 'Paid Date', 'Paid By',
               'Signed Note', 'Narration', 'Created By', 'Created'])
    for d in delivery_list:
        ws.append([d['delivery_note_number'], d['customer_name'], d['description'] or '',
                   d['driver_name'] or '', d['driver_vehicle'] or '', d['delivery_date'] or '',
                   d['transportation_charge'] or 0, 'Paid' if d['charge_paid'] else 'Unpaid',
                   d['payment_method'] or '', d['paid_date'] or '', d['paid_by'] or '',
                   d['signed_note_status'], d['narration'] or '', d['creator_name'] or '', d['created_at'] or ''])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return send_file(output, download_name='deliveries.xlsx', as_attachment=True,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# ── User Management (Admin) ─────────────────────────────────
@app.route('/users')
@admin_required
def users():
    db = get_db()
    user_list = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    db.close()
    return render_template('users.html', users=user_list)


@app.route('/users/add', methods=['GET', 'POST'])
@super_admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        role = request.form.get('role', 'user')

        if not username or not password or not full_name:
            flash('Username, password and full name are required.', 'danger')
            return render_template('user_form.html', user=None)

        db = get_db()
        existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            db.close()
            flash('Username already exists.', 'danger')
            return render_template('user_form.html', user=None)

        db.execute('''
            INSERT INTO users (username, password_hash, full_name, email, phone, role)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, _hash_pw(password), full_name, email, phone, role))
        db.commit()
        log_activity(current_user.id, 'add_user', f'Created user: {username} ({full_name}) - Role: {role}')
        db.close()
        flash('User created successfully.', 'success')
        return redirect(url_for('users'))

    return render_template('user_form.html', user=None)


@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@super_admin_required
def edit_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not user:
        db.close()
        flash('User not found.', 'danger')
        return redirect(url_for('users'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        role = request.form.get('role', 'user')
        is_active = 1 if request.form.get('is_active') else 0
        new_password = request.form.get('password', '').strip()

        if not full_name:
            flash('Full name is required.', 'danger')
        else:
            if new_password:
                db.execute('''
                    UPDATE users SET full_name=?, email=?, phone=?, role=?, is_active=?, password_hash=?
                    WHERE id=?
                ''', (full_name, email, phone, role, is_active, _hash_pw(new_password), user_id))
            else:
                db.execute('''
                    UPDATE users SET full_name=?, email=?, phone=?, role=?, is_active=?
                    WHERE id=?
                ''', (full_name, email, phone, role, is_active, user_id))
            db.commit()
            log_activity(current_user.id, 'edit_user', f'Edited user #{user_id}: {full_name} - Role: {role}, Active: {is_active}')
            db.close()
            flash('User updated successfully.', 'success')
            return redirect(url_for('users'))

    db.close()
    return render_template('user_form.html', user=user)


@app.route('/users/toggle/<int:user_id>')
@super_admin_required
def toggle_user(user_id):
    if user_id == current_user.id:
        flash('You cannot deactivate yourself.', 'danger')
        return redirect(url_for('users'))

    db = get_db()
    user = db.execute('SELECT is_active FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        new_status = 0 if user['is_active'] else 1
        db.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
        db.commit()
        log_activity(current_user.id, 'toggle_user', f'User #{user_id} {"activated" if new_status else "deactivated"}')
        flash('User status updated.', 'success')
    db.close()
    return redirect(url_for('users'))


# ── Delivery Person Management ────────────────────────────────
@app.route('/delivery-persons')
@login_required
def delivery_persons():
    db = get_db()
    persons = db.execute('SELECT * FROM delivery_persons ORDER BY name').fetchall()
    db.close()
    return render_template('delivery_persons.html', persons=persons)


@app.route('/delivery-persons/add', methods=['GET', 'POST'])
@login_required
def add_delivery_person():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        mobile = request.form.get('mobile', '').strip()
        iqama_id = request.form.get('iqama_id', '').strip()
        vehicle_no = request.form.get('vehicle_no', '').strip()

        if not name:
            flash('Name is required.', 'danger')
            return render_template('delivery_person_form.html', person=None)

        db = get_db()
        db.execute('''
            INSERT INTO delivery_persons (name, mobile, iqama_id, vehicle_no)
            VALUES (?, ?, ?, ?)
        ''', (name, mobile, iqama_id, vehicle_no))
        db.commit()
        log_activity(current_user.id, 'add_delivery_person', f'Added delivery person: {name} - Mobile: {mobile}, Vehicle: {vehicle_no}')
        db.close()
        flash('Delivery person added successfully.', 'success')
        return redirect(url_for('delivery_persons'))

    return render_template('delivery_person_form.html', person=None)


@app.route('/delivery-persons/edit/<int:person_id>', methods=['GET', 'POST'])
@login_required
def edit_delivery_person(person_id):
    db = get_db()
    person = db.execute('SELECT * FROM delivery_persons WHERE id = ?', (person_id,)).fetchone()

    if not person:
        db.close()
        flash('Delivery person not found.', 'danger')
        return redirect(url_for('delivery_persons'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        mobile = request.form.get('mobile', '').strip()
        iqama_id = request.form.get('iqama_id', '').strip()
        vehicle_no = request.form.get('vehicle_no', '').strip()
        is_active = 1 if request.form.get('is_active') else 0

        if not name:
            flash('Name is required.', 'danger')
        else:
            db.execute('''
                UPDATE delivery_persons SET name=?, mobile=?, iqama_id=?, vehicle_no=?, is_active=?
                WHERE id=?
            ''', (name, mobile, iqama_id, vehicle_no, is_active, person_id))
            db.commit()
            log_activity(current_user.id, 'edit_delivery_person', f'Edited delivery person #{person_id}: {name}')
            db.close()
            flash('Delivery person updated successfully.', 'success')
            return redirect(url_for('delivery_persons'))

    db.close()
    return render_template('delivery_person_form.html', person=person)


@app.route('/delivery-persons/delete/<int:person_id>')
@admin_required
def delete_delivery_person(person_id):
    db = get_db()
    person = db.execute('SELECT name FROM delivery_persons WHERE id = ?', (person_id,)).fetchone()
    db.execute('DELETE FROM delivery_persons WHERE id = ?', (person_id,))
    db.commit()
    log_activity(current_user.id, 'delete_delivery_person', f'Deleted delivery person #{person_id}: {person["name"] if person else "Unknown"}')
    db.close()
    flash('Delivery person deleted.', 'success')
    return redirect(url_for('delivery_persons'))


# ── Activity Logs (Admin) ────────────────────────────────────
@app.route('/logs')
@admin_required
def activity_logs():
    db = get_db()
    user_filter = request.args.get('user', '')
    action_filter = request.args.get('action', '')

    query = '''
        SELECT l.*, u.full_name, u.username
        FROM activity_logs l
        LEFT JOIN users u ON l.user_id = u.id
        WHERE 1=1
    '''
    params = []

    if user_filter:
        query += ' AND l.user_id = ?'
        params.append(int(user_filter))

    if action_filter:
        query += ' AND l.action = ?'
        params.append(action_filter)

    query += ' ORDER BY l.created_at DESC LIMIT 500'

    logs = db.execute(query, params).fetchall()
    users = db.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()
    db.close()

    return render_template('logs.html', logs=logs, users=users,
                           user_filter=user_filter, action_filter=action_filter)


# ── Messaging ────────────────────────────────────────────────
@app.route('/messages')
@login_required
def messages_inbox():
    db = get_db()
    # Get all users this person has conversations with
    conversations = db.execute('''
        SELECT u.id, u.full_name, u.profile_pic, u.role,
            (SELECT COUNT(*) FROM messages WHERE sender_id = u.id AND receiver_id = ? AND is_read = 0) as unread,
            (SELECT MAX(created_at) FROM messages WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id)) as last_msg_time,
            (SELECT message FROM messages WHERE ((sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id)) ORDER BY created_at DESC LIMIT 1) as last_msg
        FROM users u
        WHERE u.id != ? AND u.is_active = 1
        ORDER BY last_msg_time DESC NULLS LAST, u.full_name ASC
    ''', (current_user.id, current_user.id, current_user.id, current_user.id, current_user.id, current_user.id)).fetchall()
    db.close()
    return render_template('messages_inbox.html', conversations=conversations)


@app.route('/messages/<int:user_id>')
@login_required
def messages_chat(user_id):
    db = get_db()
    other_user = db.execute('SELECT id, full_name, profile_pic, role FROM users WHERE id = ?', (user_id,)).fetchone()
    if not other_user:
        db.close()
        flash('User not found.', 'danger')
        return redirect(url_for('messages_inbox'))

    # Mark as read
    db.execute('UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0',
               (user_id, current_user.id))
    db.commit()

    chat = db.execute('''
        SELECT m.*, s.full_name as sender_name, s.profile_pic as sender_pic
        FROM messages m
        LEFT JOIN users s ON m.sender_id = s.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at ASC
    ''', (current_user.id, user_id, user_id, current_user.id)).fetchall()
    db.close()
    return render_template('messages_chat.html', chat=chat, other_user=other_user)


@app.route('/messages/<int:user_id>/send', methods=['POST'])
@login_required
def send_message(user_id):
    message_text = request.form.get('message', '').strip()
    attachment_file = request.files.get('attachment')
    attachment_filename = None

    if attachment_file and attachment_file.filename:
        allowed_ext = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'zip'}
        ext = attachment_file.filename.rsplit('.', 1)[1].lower() if '.' in attachment_file.filename else ''
        if ext in allowed_ext:
            safe_name = secure_filename(attachment_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            attachment_filename = f'msg_{current_user.id}_{timestamp}_{safe_name}'
            attachment_file.save(os.path.join(UPLOAD_FOLDER, attachment_filename))
        else:
            flash('Invalid attachment type.', 'danger')
            return redirect(url_for('messages_chat', user_id=user_id))

    if not message_text and not attachment_filename:
        flash('Please enter a message or attach a file.', 'warning')
        return redirect(url_for('messages_chat', user_id=user_id))

    db = get_db()
    db.execute('INSERT INTO messages (sender_id, receiver_id, message, attachment) VALUES (?, ?, ?, ?)',
               (current_user.id, user_id, message_text, attachment_filename))
    db.commit()
    db.close()

    # Send notification
    preview = (message_text[:50] + '...') if len(message_text) > 50 else message_text
    if attachment_filename and not message_text:
        preview = 'Sent an attachment'
    send_notification(user_id, 'New Message', f'{current_user.full_name}: {preview}', 'message', url_for('messages_chat', user_id=current_user.id))

    return redirect(url_for('messages_chat', user_id=user_id))


@app.route('/messages/<int:user_id>/new')
@login_required
def get_new_messages(user_id):
    after_id = request.args.get('after', 0, type=int)
    db = get_db()
    # Mark incoming as read
    db.execute('UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0',
               (user_id, current_user.id))
    db.commit()
    msgs = db.execute('''
        SELECT m.id, m.sender_id, m.message, m.attachment, m.created_at, s.full_name as sender_name
        FROM messages m
        LEFT JOIN users s ON m.sender_id = s.id
        WHERE m.id > ? AND ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
        ORDER BY m.created_at ASC
    ''', (after_id, current_user.id, user_id, user_id, current_user.id)).fetchall()
    db.close()
    result = []
    for m in msgs:
        result.append({
            'id': m['id'],
            'sender_id': m['sender_id'],
            'message': m['message'] or '',
            'attachment': m['attachment'] or '',
            'created_at': m['created_at'] or '',
            'sender_name': m['sender_name'] or ''
        })
    return jsonify(result)


@app.route('/messages/<int:user_id>/send-ajax', methods=['POST'])
@login_required
def send_message_ajax(user_id):
    message_text = request.form.get('message', '').strip()
    attachment_file = request.files.get('attachment')
    attachment_filename = None

    if attachment_file and attachment_file.filename:
        allowed_ext = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'zip'}
        ext = attachment_file.filename.rsplit('.', 1)[1].lower() if '.' in attachment_file.filename else ''
        if ext in allowed_ext:
            safe_name = secure_filename(attachment_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            attachment_filename = f'msg_{current_user.id}_{timestamp}_{safe_name}'
            attachment_file.save(os.path.join(UPLOAD_FOLDER, attachment_filename))
        else:
            return jsonify({'ok': False, 'error': 'Invalid file type'}), 400

    if not message_text and not attachment_filename:
        return jsonify({'ok': False, 'error': 'Empty message'}), 400

    db = get_db()
    db.execute('INSERT INTO messages (sender_id, receiver_id, message, attachment) VALUES (?, ?, ?, ?)',
               (current_user.id, user_id, message_text, attachment_filename))
    db.commit()
    db.close()

    preview = (message_text[:50] + '...') if len(message_text) > 50 else message_text
    if attachment_filename and not message_text:
        preview = 'Sent an attachment'
    send_notification(user_id, 'New Message', f'{current_user.full_name}: {preview}', 'message', url_for('messages_chat', user_id=current_user.id))

    return jsonify({'ok': True})


@app.route('/messages/unread-count')
@login_required
def unread_messages_count():
    db = get_db()
    count = db.execute('SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0',
                      (current_user.id,)).fetchone()[0]
    db.close()
    return jsonify({'count': count})


@app.route('/messages/<int:user_id>/delete/<int:msg_id>', methods=['POST'])
@login_required
def delete_message(user_id, msg_id):
    db = get_db()
    msg = db.execute('SELECT * FROM messages WHERE id = ?', (msg_id,)).fetchone()
    if not msg or msg['sender_id'] != current_user.id:
        db.close()
        return jsonify({'ok': False, 'error': 'Cannot delete this message'}), 403
    # Delete attachment file if exists
    if msg['attachment']:
        att_path = os.path.join(UPLOAD_FOLDER, msg['attachment'])
        if os.path.exists(att_path):
            os.remove(att_path)
    db.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
    db.commit()
    db.close()
    return jsonify({'ok': True})


@app.route('/messages/<int:user_id>/clear', methods=['POST'])
@login_required
def clear_messages(user_id):
    db = get_db()
    # Get attachments to delete
    attachments = db.execute('''
        SELECT attachment FROM messages
        WHERE sender_id = ? AND receiver_id = ? AND attachment IS NOT NULL AND attachment != ''
    ''', (current_user.id, user_id)).fetchall()
    for a in attachments:
        att_path = os.path.join(UPLOAD_FOLDER, a['attachment'])
        if os.path.exists(att_path):
            os.remove(att_path)
    # Delete only messages sent by current user
    db.execute('DELETE FROM messages WHERE sender_id = ? AND receiver_id = ?',
               (current_user.id, user_id))
    db.commit()
    db.close()
    flash('Your messages have been cleared.', 'success')
    return redirect(url_for('messages_chat', user_id=user_id))


# ── Settings ─────────────────────────────────────────────────
@app.route('/settings')
@admin_required
def settings():
    return redirect(url_for('print_settings'))


@app.route('/settings/print', methods=['GET', 'POST'])
@admin_required
def print_settings():
    db = get_db()
    if request.method == 'POST':
        keys = ['print_paper_size', 'print_orientation', 'print_company_name', 'print_show_logo']
        for k in keys:
            val = request.form.get(k, '')
            if k == 'print_show_logo':
                val = '1' if request.form.get(k) else '0'
            db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (k, val))
        db.commit()
        log_activity(current_user.id, 'update_settings', 'Updated print settings')
        flash('Print settings saved.', 'success')
        db.close()
        return redirect(url_for('print_settings'))

    rows = db.execute('SELECT key, value FROM settings').fetchall()
    db.close()
    s = {r['key']: r['value'] for r in rows}
    return render_template('settings_print.html', settings=s)


@app.route('/settings/roles')
@admin_required
def role_settings():
    db = get_db()
    users_by_role = db.execute('''
        SELECT id, full_name, username, role, is_active FROM users ORDER BY
        CASE role WHEN 'super_admin' THEN 1 WHEN 'admin' THEN 2 ELSE 3 END, full_name
    ''').fetchall()
    db.close()
    return render_template('settings_roles.html', users=users_by_role)


# ── Backup ───────────────────────────────────────────────────
backup_thread = None
backup_stop_event = threading.Event()


def do_backup():
    """Create a timestamped backup of the database."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f'backup_{timestamp}.db'
    src = DB_PATH
    dst = os.path.join(BACKUP_FOLDER, backup_name)
    shutil.copy2(src, dst)
    # Keep only the last 20 backups
    backups = sorted(
        [f for f in os.listdir(BACKUP_FOLDER) if f.startswith('backup_') and f.endswith('.db')],
        reverse=True
    )
    for old in backups[20:]:
        os.remove(os.path.join(BACKUP_FOLDER, old))
    return backup_name


def auto_backup_worker():
    """Background thread that backs up the DB at the configured interval."""
    while not backup_stop_event.is_set():
        try:
            db = get_db()
            rows = db.execute("SELECT key, value FROM settings WHERE key IN ('auto_backup', 'backup_interval_minutes')").fetchall()
            db.close()
            s = {r['key']: r['value'] for r in rows}
            if s.get('auto_backup') == '1':
                interval = int(s.get('backup_interval_minutes', '60'))
                do_backup()
                backup_stop_event.wait(interval * 60)
            else:
                backup_stop_event.wait(30)  # check again in 30s
        except Exception:
            backup_stop_event.wait(60)


def start_auto_backup():
    global backup_thread
    if backup_thread and backup_thread.is_alive():
        return
    backup_stop_event.clear()
    backup_thread = threading.Thread(target=auto_backup_worker, daemon=True)
    backup_thread.start()


@app.route('/settings/backup', methods=['GET', 'POST'])
@admin_required
def backup_settings():
    db = get_db()
    if request.method == 'POST':
        auto_backup = '1' if request.form.get('auto_backup') else '0'
        interval = request.form.get('backup_interval_minutes', '60')
        try:
            interval = str(max(1, int(interval)))
        except ValueError:
            interval = '60'
        db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('auto_backup', auto_backup))
        db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('backup_interval_minutes', interval))
        db.commit()
        log_activity(current_user.id, 'update_settings', f'Updated backup settings: auto={auto_backup}, interval={interval}min')
        flash('Backup settings saved.', 'success')
        db.close()
        # Restart the backup thread so it picks up new settings
        backup_stop_event.set()
        _time.sleep(0.2)
        start_auto_backup()
        return redirect(url_for('backup_settings'))

    rows = db.execute('SELECT key, value FROM settings').fetchall()
    s = {r['key']: r['value'] for r in rows}

    # List existing backups
    backups = []
    if os.path.exists(BACKUP_FOLDER):
        for f in sorted(os.listdir(BACKUP_FOLDER), reverse=True):
            if f.startswith('backup_') and f.endswith('.db'):
                fpath = os.path.join(BACKUP_FOLDER, f)
                size_mb = round(os.path.getsize(fpath) / (1024 * 1024), 2)
                backups.append({'name': f, 'size': size_mb,
                                'date': f.replace('backup_', '').replace('.db', '').replace('_', ' ')})
    db.close()
    return render_template('settings_backup.html', settings=s, backups=backups)


@app.route('/backup/now', methods=['POST'])
@admin_required
def backup_now():
    try:
        name = do_backup()
        log_activity(current_user.id, 'manual_backup', f'Created manual backup: {name}')
        flash(f'Backup created: {name}', 'success')
    except Exception as e:
        flash(f'Backup failed: {str(e)}', 'danger')
    return redirect(url_for('backup_settings'))


@app.route('/backup/download/<filename>')
@admin_required
def download_backup(filename):
    safe_name = secure_filename(filename)
    fpath = os.path.join(BACKUP_FOLDER, safe_name)
    if not os.path.exists(fpath):
        flash('Backup not found.', 'danger')
        return redirect(url_for('backup_settings'))
    return send_file(fpath, download_name=safe_name, as_attachment=True)


@app.route('/backup/delete/<filename>', methods=['POST'])
@admin_required
def delete_backup(filename):
    safe_name = secure_filename(filename)
    fpath = os.path.join(BACKUP_FOLDER, safe_name)
    if os.path.exists(fpath):
        os.remove(fpath)
        flash('Backup deleted.', 'success')
    else:
        flash('Backup not found.', 'danger')
    return redirect(url_for('backup_settings'))


@app.context_processor
def inject_settings():
    if current_user.is_authenticated:
        db = get_db()
        try:
            rows = db.execute('SELECT key, value FROM settings').fetchall()
            s = {r['key']: r['value'] for r in rows}
        except Exception:
            s = {}
        db.close()
        return {'app_settings': s, 'now': datetime.now}
    return {'app_settings': {}, 'now': datetime.now}


# ── Initialize ───────────────────────────────────────────────
def create_default_admin():
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE role = 'super_admin'").fetchone()
    if not existing:
        db.execute('''
            INSERT INTO users (username, password_hash, full_name, email, pin_hash, role)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', _hash_pw('admin123'), 'Super Admin', 'admin@example.com', _hash_pw('1234'), 'super_admin'))
        db.commit()
        print("✅ Default super admin created: username='admin', password='admin123', PIN='1234'")
    db.close()


if __name__ == '__main__':
    init_db()
    create_default_admin()
    start_auto_backup()
    print("🚀 Server starting at http://127.0.0.1:5050")
    app.run(debug=True, host='0.0.0.0', port=5050)
