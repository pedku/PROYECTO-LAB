import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from flask_migrate import Migrate, upgrade
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from flask_cors import CORS
import pytz

# Cargar las variables de entorno desde el archivo .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv( 'DATABASE_URL', 'postgresql://postgres:Pc200172@localhost/laboratorios_db')
#app.config['SQLALCHEMY_DATABASE_URI'] =  'postgresql://postgres:Pc200172@localhost/laboratorios_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

CORS(app)

# Configurar la zona horaria de Colombia
COLOMBIA_TZ = pytz.timezone('America/Bogota')

#csrf = CSRFProtect(app)

#csrf.init_app(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('Unauthorized access', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Models
class Profe(db.Model):
    __tablename__ = 'profes'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False)
    qr_code = db.Column(db.String(200), nullable=False, unique=True)
    
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'root', 'admin', 'viewer'

class Laboratory(db.Model):
    __tablename__ = 'laboratories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True) 
    description = db.Column(db.String(255))

class Schedule(db.Model):
    __tablename__ = 'schedules'
    id = db.Column(db.Integer, primary_key=True)
    lab_id = db.Column(db.Integer, db.ForeignKey('laboratories.id'), nullable=False)
    profe_id = db.Column(db.Integer, db.ForeignKey('profes.id'), nullable=False)
    professor = db.relationship('Profe', backref='schedules')
    lab = db.relationship('Laboratory', backref='schedules')
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    id = db.Column(db.Integer, primary_key=True)
    profe_id = db.Column(db.Integer, db.ForeignKey('profes.id'), nullable=False)
    lab_id = db.Column(db.Integer, db.ForeignKey('laboratories.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(COLOMBIA_TZ))
    professor = db.relationship('Profe', backref='access_logs')
    lab = db.relationship('Laboratory', backref='access_logs')

def create_initial_user():
    if not User.query.filter_by(username='root').first():
        password_hash = generate_password_hash('1234')
        root_user = User(username='root', password_hash=password_hash, role='root')
        db.session.add(root_user)
        db.session.commit()
        print("Usuario root creado")

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('dashboard.html', user=user)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/horario', methods=['GET'])
def horario():
    schedules = Schedule.query.all()
    return render_template('horario.html', schedules=schedules)

@app.route('/delete_lab', methods=['POST'])
def delete_lab():
    if 'role' in session and session['role'] in ['root', 'admin']:
        lab_id = request.form['lab_id']
        lab = Laboratory.query.get(lab_id)
        if lab:
            db.session.delete(lab)
            db.session.commit()
            flash('Laboratorio eliminado exitosamente')
        else:
            flash('Laboratorio no encontrado')
        return redirect(url_for('manage_labs'))
    flash('Acceso no autorizado')
    return redirect(url_for('home'))

@app.route('/change_lab_details', methods=['POST'])
def change_lab_details():
    if 'role' in session and session['role'] in ['root', 'admin']:
        lab_id = request.form['lab_id']
        lab = Laboratory.query.get(lab_id)
        if lab:
            lab.name = request.form['name']
            lab.description = request.form['description']
            db.session.commit()
            flash('Detalles del laboratorio actualizados exitosamente')
        else:
            flash('Laboratorio no encontrado')
        return redirect(url_for('manage_labs'))
    flash('Acceso no autorizado')
    return redirect(url_for('home'))

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('root')
def manage_users():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Nombre de usuario Ya Existente', 'warning')
                return redirect(url_for('manage_users'))
            password_hash = generate_password_hash(password)
            new_user = User(username=username, password_hash=password_hash, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully')
        elif action == 'delete':
            user_id = request.form['user_id']
            User.query.filter_by(id=user_id).delete()
            db.session.commit()
            flash('User deleted successfully')
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/labs', methods=['GET', 'POST'])
def manage_labs():
    if 'role' in session and session['role'] in ['root', 'admin']:
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            new_lab = Laboratory(name=name, description=description)
            if Laboratory.query.filter_by(name=name).first():
                flash('Laboratorio Ya EXISTENTE ', 'warning')
                return redirect(url_for('manage_labs'))
            db.session.add(new_lab)
            db.session.commit()
            flash('Laboratory added successfully' , 'success')
        labs = Laboratory.query.all()
        return render_template('labs.html', labs=labs)
    flash('Unauthorized access' , 'danger')
    return redirect(url_for('home'))

@app.route('/manage_profe', methods=['GET', 'POST'])
def manage_profe():
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                name = request.form['name']
                qr_code = request.form['qr_code']
                existing_profe = Profe.query.filter_by(qr_code=qr_code).first()
                if existing_profe:
                    flash('El código QR ya existe', 'warning')
                    return redirect(url_for('manage_profe'))

                new_user = Profe(username=name, qr_code=qr_code)
                db.session.add(new_user)
            elif action == 'delete':
                user_id = request.form['user_id']
                Profe.query.filter_by(id=user_id).delete()
            db.session.commit()
            flash('Operación exitosa', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    users = Profe.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/edit_user', methods=['POST'])
def edit_user():
    try:
        user_id = request.form['user_id']
        user = Profe.query.get(user_id)
        user.username = request.form['username']
        user.qr_code = request.form['qr_code']
        db.session.commit()
        flash('Usuario actualizado exitosamente', 'success')
        return redirect(url_for('manage_profe'))
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}', 'danger')
    return redirect(url_for('manage_profe'))

@app.route('/manage_schedule', methods=['GET', 'POST'])
def manage_schedule():
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                lab_id = request.form['lab_id']
                profe_id = request.form['profe_id']
                date = request.form['date']
                start_time = request.form['start_time']
                end_time = request.form['end_time']
                date_converted = datetime.strptime(date, '%Y-%m-%d').date()
              
                # Verificar si el profesor ya está asignado a una clase en el mismo horario
                existing_schedule = Schedule.query.filter(
                    Schedule.profe_id == profe_id,
                    Schedule.date == date,
                    Schedule.start_time < end_time,
                    Schedule.end_time > start_time
                    
                ).first()

                # Verificar si el laboratorio ya está asignado a una clase en el mismo horario
                existing_schedule_lab = Schedule.query.filter(
                    Schedule.lab_id == lab_id,
                    Schedule.date == date,
                    Schedule.start_time < end_time,
                    Schedule.end_time > start_time
                ).first()
                if existing_schedule_lab:
                    flash('El laboratorio ya está asignado a una clase en el mismo horario', 'warning')
                    return redirect(url_for('manage_schedule'))
                
                # Verificar si la fecha es anterior a la fecha actual
                if date_converted < datetime.now(COLOMBIA_TZ).date():
                    flash('La fecha no puede ser anterior a la fecha actual', 'warning')
                    return redirect(url_for('manage_schedule'))
              
                # Verificar si la hora de finalización es mayor que la hora de inicio
                if end_time <= start_time:
                    flash('La hora de finalización debe ser mayor que la hora de inicio', 'warning')
                    return redirect(url_for('manage_schedule'))
              
                # Verificar si el laboratorio ya está asignado a una clase en el mismo horario
                if existing_schedule:
                    flash('El profesor ya está asignado a una clase en el mismo horario', 'warning')
                    return redirect(url_for('manage_schedule'))
                
                # Guardar la clase en la base de datos
                new_schedule = Schedule(lab_id=lab_id, profe_id=profe_id, date=date, start_time=start_time, end_time=end_time)
                db.session.add(new_schedule)
                db.session.commit()
                flash('Operation successful', 'success')
            elif action == 'delete':
                schedule_id = request.form['schedule_id']
                Schedule.query.filter_by(id=schedule_id).delete()
            elif action == 'edit':
                schedule_id = request.form['schedule_id']
                schedule = Schedule.query.get(schedule_id)
                schedule.lab_id = request.form['lab_id']
                schedule.profe_id = request.form['profe_id']
                schedule.date = request.form['date']
                schedule.start_time = request.form['start_time']
                schedule.end_time = request.form['end_time']
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}', 'danger')
    labs = Laboratory.query.all()
    profes = Profe.query.all()
    schedules = Schedule.query.all()
    return render_template('schedule.html', labs=labs, profes=profes, schedules=schedules)

@app.route('/logs')
@login_required
@role_required('root', 'admin')
def view_logs():
    try:
        logs = AccessLog.query.all()
        return render_template('logs.html', logs=logs)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')
        return redirect(url_for('home'))

@app.route('/qr', methods=['POST'])
def validate_qr():
    try:
        data = request.json
        print(data)
        lab_name = data.get('labID')  # Obtener el nombre del laboratorio
        qr_code = data.get('qr')
        current_time = datetime.now(COLOMBIA_TZ).time()
        current_date = datetime.now(COLOMBIA_TZ).date()
        
        print(f"lab_name: {lab_name}, qr_code: {qr_code}, current_time: {current_time}, current_date: {current_date}")
        
        profe = Profe.query.filter_by(qr_code=qr_code).first()
        if not profe:
            print("Invalid QR code")
            return jsonify({'status': 'unauthorized', 'message': 'Invalid QR code'})

        print(f"Profe ID: {profe.id}")
        
        schedule = Schedule.query.join(Laboratory).filter(
            Schedule.profe_id == profe.id,
            Schedule.date == current_date,
            Schedule.start_time <= current_time,
            Schedule.end_time >= current_time,
            Laboratory.name == lab_name
        ).first()

        if schedule:
            print(f"Schedule found: {schedule.id}")
            logs = AccessLog(profe_id=profe.id, lab_id=schedule.lab_id, timestamp=datetime.now(COLOMBIA_TZ).strftime('%Y-%m-%d %H:%M'))
            db.session.add(logs)
            db.session.commit()
            return jsonify({'status': 'success', 'labID': lab_name})
        else:
            print("No valid schedule found")
            return jsonify({'status': 'unauthorized', 'message': 'No valid schedule found'})
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'})

@app.route('/change_user_details', methods=['POST'])
@login_required
@role_required('root')
def change_user_details():
    try:
        user_id = request.form['user_id']
        username = request.form['username']
        new_password = request.form['new_password']
        
        user = User.query.get(user_id)
        if user:
            user.username = username
            if new_password:
                user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('User details updated successfully')
        else:
            flash('User not found')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}', 'danger')
    return redirect(url_for('manage_users'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_initial_user()
        app.run(debug=True)
