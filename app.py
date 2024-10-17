from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from datetime import datetime
from collections import defaultdict
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///funds.db'
app.config['SECRET_KEY'] = 'SRTENAS74293URONSHDGCVYWZKAUQK098387412SYYVEDSA'  # Change this to a random secret key
db = SQLAlchemy(app)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')
    is_password_changed = db.Column(db.Boolean, default=False)
    deposits = db.relationship('Deposit', backref='user', lazy='dynamic')
    withdrawals = db.relationship('Withdrawal', backref='user', lazy='dynamic')

    def __init__(self, name, email, password, role='member'):
        self.name = name
        self.email = email
        self.password = generate_password_hash(password)
        self.role = role

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def total_deposited(self):
        return sum(deposit.amount for deposit in self.deposits)

    def total_withdrawn(self):
        return sum(withdrawal.amount for withdrawal in self.withdrawals)

    def balance(self):
        return self.total_deposited() - self.total_withdrawn()


class Deposit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    withdrawal_type = db.Column(db.String(20), nullable=False)  # 'personal' or 'group'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('audit_logs', lazy='dynamic'))

def log_action(user_id, action):
    log = AuditLog(user_id=user_id, action=action)
    db.session.add(log)
    db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function




def password_change_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        if not user:
            session.pop('user_id', None)  # Clear invalid session
            return redirect(url_for('login'))

        if not user.is_password_changed:
            return redirect(url_for('change_password'))

        return f(*args, **kwargs)

    return decorated_function

@app.route('/')
def home():
    return render_template('main.html')

@app.route('/index')
@login_required
def index():
    users = User.query.all()
    total_deposited = sum(user.total_deposited() for user in users)
    total_withdrawn = sum(user.total_withdrawn() for user in users)
    total_balance = total_deposited - total_withdrawn
    return render_template('index.html', users=users, total_deposited=total_deposited, total_withdrawn=total_withdrawn, total_balance=total_balance)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('You need to be an admin to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def users():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('users'))

        new_user = User(name=name, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        log_action(session['user_id'], f"Created new user: {name} ({email}) with role: {role}")
        flash('New user added successfully.', 'success')
        return redirect(url_for('users'))

    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            log_action(user.id, f"User logged in: {user.email}")
            if not user.is_password_changed:
                return redirect(url_for('change_password'))
            return redirect(url_for('user_dashboard'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        new_password = request.form['new_password']
        user.password = generate_password_hash(new_password)
        user.is_password_changed = True
        db.session.commit()
        log_action(user.id, "Changed password")
        return redirect(url_for('user_dashboard'))
    return render_template('change_password.html')

@app.route('/deposit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@password_change_required
def deposit(user_id):
    user = User.query.get(user_id)
    if request.method == 'POST':
        amount = int(request.form['amount'])
        date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        deposit = Deposit(amount=amount, date=date, user=user)
        db.session.add(deposit)
        db.session.commit()
        log_action(user.id, f"Deposited {amount} on {date}")
        return redirect(url_for('user_dashboard'))
    return render_template('deposit.html', user=user)


# Update the personal_withdrawal route

@app.route('/personal_withdrawal/<int:user_id>', methods=['GET', 'POST'])
@login_required
@password_change_required
def personal_withdrawal(user_id):
    user = User.query.get_or_404(user_id)
    current_user = User.query.get(session['user_id'])

    if current_user.id != user.id and current_user.role != 'admin':
        flash('You can only make personal withdrawals from your own account.', 'danger')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        amount = int(request.form['amount'])
        date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        reason = request.form['reason']

        if amount > user.balance():
            flash('Insufficient funds for this withdrawal.', 'danger')
            return redirect(url_for('personal_withdrawal', user_id=user.id))

        withdrawal = Withdrawal(amount=amount, date=date, reason=reason, user=user, withdrawal_type='personal')
        db.session.add(withdrawal)

        action_description = f"Personal withdrawal of {amount} on {date} for reason: {reason}"
        if current_user.id != user.id:
            action_description = f"Admin {current_user.name} initiated: " + action_description

        log_action(user.id, action_description)

        db.session.commit()

        flash('Personal withdrawal successful.', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('personal_withdrawal.html', user=user, current_user=current_user)


# Update the withdraw route (for group withdrawals)

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
@password_change_required
def withdraw():
    if request.method == 'POST':
        withdrawal_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        reason = "Group withdrawal - " + request.form['reason']
        total_amount = int(request.form['amount'])

        # Get all unique users who have made deposits up to the withdrawal date
        user_query = (db.session.query(User)
                      .join(Deposit)
                      .filter(Deposit.date <= withdrawal_date)
                      .distinct())

        eligible_users = user_query.all()

        if not eligible_users:
            flash('No eligible users found for withdrawal', 'danger')
            return redirect(url_for('withdraw'))

        # Calculate equal share for each user
        num_users = len(eligible_users)
        amount_per_user = round(total_amount / num_users)

        # Create one withdrawal per user
        for user in eligible_users:
            user_balance = user.balance()

            if user_balance < amount_per_user:
                flash(f'Warning: User {user.name} has insufficient balance', 'warning')
                continue

            withdrawal = Withdrawal(
                amount=amount_per_user,
                date=withdrawal_date,
                reason=reason,
                user=user,
                withdrawal_type='group'
            )
            db.session.add(withdrawal)
            log_action(user.id,
                       f"Group withdrawal of {amount_per_user} on {withdrawal_date} for reason: {reason}")

        db.session.commit()
        flash('Group withdrawal completed successfully', 'success')
        return redirect(url_for('index'))

    return render_template('withdrawal.html')
# Update the user_dashboard route

@app.route('/user_dashboard')
@login_required
@password_change_required
def user_dashboard():
    user = User.query.get(session['user_id'])

    page_deposit = request.args.get('page_deposit', 1, type=int)
    page_personal_withdrawal = request.args.get('page_personal_withdrawal', 1, type=int)
    page_group_withdrawal = request.args.get('page_group_withdrawal', 1, type=int)

    deposits = user.deposits.order_by(Deposit.date.desc()).paginate(page=page_deposit, per_page=5, error_out=False)

    personal_withdrawals = user.withdrawals.filter_by(withdrawal_type='personal').order_by(
        Withdrawal.date.desc()).paginate(page=page_personal_withdrawal, per_page=5, error_out=False)

    group_withdrawals = user.withdrawals.filter_by(withdrawal_type='group').order_by(Withdrawal.date.desc()).paginate(
        page=page_group_withdrawal, per_page=5, error_out=False)

    return render_template('user_dashboard.html', user=user, deposits=deposits,
                           personal_withdrawals=personal_withdrawals,
                           group_withdrawals=group_withdrawals)


@app.route('/bulk_deposit', methods=['GET', 'POST'])
@login_required
@password_change_required
def bulk_deposit():
    if request.method == 'POST':
        data = request.json
        for entry in data:
            date = datetime.strptime(entry['date'], '%Y-%m-%d').date()
            for user_id in entry['users']:
                user = User.query.get(user_id)
                if user:
                    deposit = Deposit(amount=200, date=date, user=user)
                    db.session.add(deposit)
                    log_action(user.id, f"Bulk deposit of 200 on {date}")
        db.session.commit()
        return jsonify({"message": "Deposits recorded successfully"}), 200

    users = User.query.all()
    return render_template('bulk_deposit.html', users=users)

@app.route('/get_users', methods=['GET'])
@login_required
@password_change_required
def get_users():
    users = User.query.all()
    return jsonify([{"id": user.id, "name": user.name} for user in users])

@app.route('/audit_log')
@login_required
@password_change_required
def audit_log():
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Number of logs per page
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('audit_log.html', logs=logs)

def format_number(value):
    return "{:,.0f}".format(value)

app.jinja_env.filters['format_number'] = format_number

@app.route('/database_management')
@login_required
@password_change_required
def database_management():
    users = User.query.all()
    deposits = Deposit.query.all()
    withdrawals = Withdrawal.query.all()
    audit_logs = AuditLog.query.all()
    return render_template('database_management.html', users=users, deposits=deposits, withdrawals=withdrawals, audit_logs=audit_logs)

@app.route('/edit/<string:model>/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_entry(model, id):
    if model == 'user':
        entry = User.query.get_or_404(id)
    elif model == 'deposit':
        entry = Deposit.query.get_or_404(id)
    elif model == 'withdrawal':
        entry = Withdrawal.query.get_or_404(id)
    else:
        abort(404)

    if request.method == 'POST':
        old_data = str(entry.__dict__)
        if model == 'user':
            entry.name = request.form['name']
            entry.email = request.form['email']
            entry.role = request.form['role']
        elif model == 'deposit' or model == 'withdrawal':
            entry.amount = int(request.form['amount'])
            entry.date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        if model == 'withdrawal':
            entry.reason = request.form['reason']

        db.session.commit()
        new_data = str(entry.__dict__)
        log_action(session['user_id'], f"Edited {model} (ID: {id}). Old data: {old_data}. New data: {new_data}")
        flash('Entry updated successfully', 'success')
        return redirect(url_for('database_management'))

    return render_template('edit_entry.html', entry=entry, model=model)


@app.route('/delete/<string:model>/<int:id>')
@login_required
@password_change_required
def delete_entry(model, id):
    if model == 'user':
        entry = User.query.get_or_404(id)
    elif model == 'deposit':
        entry = Deposit.query.get_or_404(id)
    elif model == 'withdrawal':
        entry = Withdrawal.query.get_or_404(id)
    elif model == 'auditlog':
        entry = AuditLog.query.get_or_404(id)
    else:
        abort(404)

    entry_data = str(entry.__dict__)
    db.session.delete(entry)
    db.session.commit()
    log_action(session['user_id'], f"Deleted {model} (ID: {id}). Data: {entry_data}")
    flash('Entry deleted successfully', 'success')
    return redirect(url_for('database_management'))

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return dict(current_user=user)
    return dict(current_user=None)

def format_date(date):
    day = date.day
    suffix = 'th' if 11 <= day <= 13 else {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
    return date.strftime(f"%d{suffix} %B %Y")

app.jinja_env.filters['format_date'] = format_date




if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)