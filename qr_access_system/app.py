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
import pandas as pd
from werkzeug.utils import secure_filename
import re
from unidecode import unidecode

# Cargar las variables de entorno desde el archivo .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
#app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv( 'DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] =  'postgresql://postgres:Pc200172@localhost/laboratorios_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

CORS(app)

# Configurar la zona horaria de Colombia
COLOMBIA_TZ = pytz.timezone('America/Bogota')

#csrf = CSRFProtect(app)

#csrf.init_app(app)


# Función decoradora para requerir inicio de sesión
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Función decoradora para requerir roles específicos
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

# Modelos de la base de datos


# Modelo de usuario    
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'root', 'admin', 'viewer', 'profe', 'student'
    name = db.Column(db.String(100), nullable=False)  # Nombre del usuario
    qr_code = db.Column(db.String(200), nullable=True, unique=True)  # QR opcional para profesores y estudiantes
    schedules = db.relationship('Schedule', backref='assigned_user', cascade='all, delete-orphan')  # Renombrar backref
    logs = db.relationship('AccessLog', backref='related_user', cascade='all, delete-orphan', overlaps="user")  # Agregar overlaps

# Modelo para los laboratorios
class Laboratory(db.Model):
    __tablename__ = 'laboratories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True) 
    description = db.Column(db.String(255))

# Modelo para los horarios de las clases
class Schedule(db.Model):
    __tablename__ = 'schedules'
    id = db.Column(db.Integer, primary_key=True)
    lab_id = db.Column(db.Integer, db.ForeignKey('laboratories.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)  # Relación con User
    schedule_type = db.Column(db.String(10), nullable=False)  # 'day' o 'date'
    day_of_week = db.Column(db.String(20), nullable=True)  # Día de la semana (lunes, martes, etc.)
    date = db.Column(db.Date, nullable=True)  # Fecha específica
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    lab = db.relationship('Laboratory', backref=db.backref('schedules', cascade='all, delete-orphan'))

# Modelo para los registros de acceso
class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)  # Relación con User
    lab_id = db.Column(db.Integer, db.ForeignKey('laboratories.id', ondelete='CASCADE'), nullable=False)
    lab_name = db.Column(db.String(100), nullable=False)  # Nueva columna para almacenar el nombre del laboratorio
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(COLOMBIA_TZ))
    user = db.relationship('User', backref=db.backref('access_logs', cascade='all, delete-orphan', overlaps="logs,related_user"), overlaps="related_user")  # Agregar overlaps
    lab = db.relationship('Laboratory', backref=db.backref('access_logs', cascade='all, delete-orphan'))

# Modelo para la relación entre estudiantes y horarios
class StudentAccess(db.Model):
    __tablename__ = 'student_access'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)  # Relación con User
    schedule_id = db.Column(db.Integer, db.ForeignKey('schedules.id', ondelete='CASCADE'), nullable=False)
    access_type = db.Column(db.String(20), nullable=False)  # 'delegated' o 'personal'
    user = db.relationship('User', backref=db.backref('access', cascade='all, delete-orphan'))
    schedule = db.relationship('Schedule', backref=db.backref('student_access', cascade='all, delete-orphan'))

# Crear usuario inicial
def create_initial_user():
    if not User.query.filter_by(username='@root').first():
        password_hash = generate_password_hash('1234')
        root_user = User(username='@root', password_hash=password_hash, role='root', name='Root User')
        db.session.add(root_user)
        db.session.commit()
        print("Usuario root creado")


#Crea Nombres de usuario
def Nombre (name):
    first_name, last_name = name.split(' ', 2)[:2]
                    
    # Limpiar los datos del nombre de usuario
    first_name = unidecode(first_name).lower()
    last_name = unidecode(last_name).lower()
    first_name = re.sub(r'[^a-z]', '', first_name)
    last_name = re.sub(r'[^a-z]', '', last_name)
    
    base_username = f"@{first_name[0]}{last_name}"
    username = base_username
    counter = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1
        
    return username

def generate_qr_code():
    # Inicia con "0001" y verifica si ya existe
    base_qr_code = 1
    while True:
        qr_code = f"{base_qr_code:04d}"  # Formato de 4 dígitos, ej. "0001"
        if not User.query.filter_by(qr_code=qr_code).first():
            return qr_code
        base_qr_code += 1


# Ruta principal
@app.route('/')
def home():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])  # Actualizado a Session.get()
        return render_template('dashboard.html', user=user)
    return redirect(url_for('login'))


# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            if user.role == 'profe':
                return redirect(url_for('profile'))
            return redirect(url_for('home'))
    return render_template('login.html')

# Ruta de cierre de sesión
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Ruta para ver el horario (solo usuarios autenticados)
@app.route('/horario', methods=['GET'])
@login_required
def horario():
    schedules = Schedule.query.all()
    return render_template('horario.html', schedules=schedules)

# Ruta para gestionar laboratorios (solo usuarios root y admin)
@app.route('/labs', methods=['GET', 'POST'])
@login_required
def manage_labs():
    # Gestión de laboratorios para usuarios root y admin
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
            flash('Laboratorio agregado exitosamente', 'success')
        
        # Cargar laboratorios con horarios y profesores relacionados
        labs = Laboratory.query.options(
            db.joinedload(Laboratory.schedules)
            .joinedload(Schedule.assigned_user)
        ).all()
        return render_template('labs.html', labs=labs)

    # Visualización de laboratorios para usuarios viewer
    if 'role' in session and session['role'] in ['viewer']:
        labs = Laboratory.query.options(
            db.joinedload(Laboratory.schedules)
            .joinedload(Schedule.assigned_user)
        ).all()
        return render_template('labs.html', labs=labs)

    flash('Acceso no autorizado', 'danger')
    return redirect(url_for('home'))

"""
#ruta laboratorio viewer
@app.route('/laboratorio', methods=['POST'])
@login_required
def laboratorio():
    labs = Laboratory.query.all()
    return render_template('laboratorio.html', labs=labs)
"""

# Ruta para eliminar un laboratorio (solo usuarios root y admin)
@app.route('/delete_lab', methods=['POST'])
@login_required
@role_required('root', 'admin')
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

# Ruta para cambiar los detalles de un laboratorio (solo usuarios root y admin)
@app.route('/change_lab_details', methods=['POST'])
@login_required
@role_required('root', 'admin')
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

# Ruta para gestionar usuarios (incluye profesores y estudiantes)
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('root', 'admin')
def manage_users():
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                name = request.form['name']
                identificacion = request.form.get('identificacion', None)
                role = request.form['role']

                # Generar qr_code dinámico si no se proporciona identificación
                qr_code = identificacion if identificacion else generate_qr_code()

                # Verificar si la identificación ya está registrada
                if User.query.filter_by(qr_code=qr_code).first():
                    flash('La identificación ya está registrada', 'warning')
                    return redirect(url_for('manage_users'))

                # Generar el nombre de usuario
                username = Nombre(name)
                password_hash = generate_password_hash(qr_code)

                # Crear el nuevo usuario
                new_user = User(username=username, password_hash=password_hash, role=role, name=name, qr_code=qr_code)
                db.session.add(new_user)
                db.session.commit()
                flash(f'Usuario agregado exitosamente con QR Code: {qr_code}', 'success')

            elif action == 'edit':
                user_id = request.form['user_id']
                user = User.query.get(user_id)
                if user:
                    # Actualizar los valores del usuario
                    new_name = request.form['name']
                    new_identificacion = request.form['identificacion']
                    new_role = request.form['role']

                    # Generar nuevo nombre de usuario y contraseña
                    new_username = Nombre(new_name)
                    new_password_hash = generate_password_hash(new_identificacion)

                    # Actualizar los campos
                    user.name = new_name
                    user.username = new_username
                    user.qr_code = new_identificacion
                    user.password_hash = new_password_hash
                    user.role = new_role

                    db.session.commit()
                    flash('Usuario actualizado exitosamente', 'success')
                else:
                    flash('Usuario no encontrado', 'danger')

            elif action == 'delete':
                user_id = request.form['user_id']
                if user_id == '1':  # No se permite eliminar el usuario root
                    flash('No puedes eliminar el usuario root', 'warning')
                else:
                    user = User.query.get(user_id)
                    if user:
                        db.session.delete(user)
                        db.session.commit()
                        flash('Usuario eliminado exitosamente', 'success')
                    else:
                        flash('Usuario no encontrado', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    users = User.query.all()
    return render_template('users.html', users=users)

# Ruta para gestionar profesores (solo usuarios admin)
@app.route('/manage_professors', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'root')
def manage_professors():
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                name = request.form['name']
                identificacion = request.form['identificacion']

                # Verificar si la identificación ya está registrada
                if User.query.filter_by(qr_code=identificacion).first():
                    flash('La identificación ya está registrada', 'warning')
                    return redirect(url_for('manage_professors'))

                # Generar el nombre de usuario y el qr_code basado en la identificación
                username = Nombre(name)
                qr_code = identificacion
                password_hash = generate_password_hash(identificacion)

                # Crear el nuevo profesor
                new_professor = User(username=username, password_hash=password_hash, role='profe', name=name, qr_code=qr_code)
                db.session.add(new_professor)
                db.session.commit()
                flash('Profesor agregado exitosamente', 'success')

            elif action == 'edit':
                user_id = request.form['user_id']
                user = User.query.get(user_id)
                if user and user.role == 'profe':
                    user.username = request.form['username']
                    user.name = request.form['name']
                    user.qr_code = request.form.get('qr_code', None)
                    db.session.commit()
                    flash('Profesor actualizado exitosamente', 'success')
                else:
                    flash('Profesor no encontrado o no válido', 'danger')

            elif action == 'delete':
                user_id = request.form['user_id']
                user = User.query.get(user_id)
                if user and user.role == 'profe':
                    db.session.delete(user)
                    db.session.commit()
                    flash('Profesor eliminado exitosamente', 'success')
                else:
                    flash('Profesor no encontrado o no válido', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    professors = User.query.filter_by(role='profe').all()
    return render_template('professors.html', professors=professors)


# Ruta para gestionar horarios (solo usuarios root y admin)
@app.route('/manage_schedule', methods=['GET', 'POST'])
@login_required
@role_required('root', 'admin')
def manage_schedule():
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                lab_id = request.form['lab_id']
                profe_id = request.form['profe_id']
                schedule_type = request.form['schedule_type']
                start_time = request.form['start_time']
                end_time = request.form['end_time']

                # Validar que el profesor exista y tenga el rol 'profe'
                professor = User.query.filter_by(id=profe_id, role='profe').first()
                if not professor:
                    flash('El profesor seleccionado no es válido', 'danger')
                    return redirect(url_for('manage_schedule'))

                if schedule_type == 'day':
                    day_of_week = request.form['day_of_week']
                    # Verificar si ya existe un horario para el día de la semana
                    existing_schedule = Schedule.query.filter(
                        Schedule.lab_id == lab_id,
                        Schedule.schedule_type == 'day',
                        Schedule.day_of_week == day_of_week,
                        Schedule.start_time < end_time,
                        Schedule.end_time > start_time
                    ).first()
                    if existing_schedule:
                        flash('Ya existe un horario para esta fecha, existe un cruce de horario', 'warning')
                        return redirect(url_for('manage_schedule'))
                    new_schedule = Schedule(
                        lab_id=lab_id,
                        user_id=profe_id,
                        schedule_type='day',
                        day_of_week=day_of_week,
                        start_time=start_time,
                        end_time=end_time
                    )
                elif schedule_type == 'date':
                    date = request.form['date']
                    # Verificar si ya existe un horario para la fecha específica
                    existing_schedule_date = Schedule.query.filter(
                        Schedule.lab_id == lab_id,
                        Schedule.schedule_type == 'date',
                        Schedule.date == date,
                        Schedule.start_time < end_time,
                        Schedule.end_time > start_time
                    ).first()
                    if existing_schedule_date:
                        flash('Ya existe un horario para esta fecha, existe un cruce de horario', 'warning')
                        return redirect(url_for('manage_schedule'))
                    new_schedule = Schedule(
                        lab_id=lab_id,
                        user_id=profe_id,
                        schedule_type='date',
                        date=date,
                        start_time=start_time,
                        end_time=end_time
                    )
                else:
                    flash('Tipo de agendamiento no válido', 'danger')
                    return redirect(url_for('manage_schedule'))

                db.session.add(new_schedule)
                db.session.commit()
                flash('Horario agregado exitosamente', 'success')

            elif action == 'delete':
                schedule_id = request.form['schedule_id']
                deleted = Schedule.query.filter_by(id=schedule_id).delete()
                db.session.commit()
                if deleted:
                    flash('Horario eliminado exitosamente', 'success')
                else:
                    flash('No se encontró el horario a eliminar', 'danger')

            elif action == 'edit':
                schedule_id = request.form['schedule_id']
                # Usar Session.get() en vez de Query.get() para evitar el warning
                schedule = db.session.get(Schedule, schedule_id)
                if schedule:
                    # Corregir casteo de lab_id y profe_id solo si son dígitos
                    lab_id = request.form['lab_id']
                    profe_id = request.form['profe_id']
                    try:
                        lab_id = int(lab_id)
                        profe_id = int(profe_id)
                    except Exception:
                        flash('Error interno: ID de laboratorio o profesor inválido.', 'danger')
                        return redirect(url_for('manage_schedule'))
                    schedule_type = request.form['schedule_type']
                    start_time = request.form['start_time']
                    end_time = request.form['end_time']

                    # Validar que el profesor exista y tenga el rol 'profe'
                    professor = User.query.filter_by(id=profe_id, role='profe').first()
                    if not professor:
                        flash('El profesor seleccionado no es válido', 'danger')
                        return redirect(url_for('manage_schedule'))

                    # Validar cruce de horario al editar
                    if schedule_type == 'day':
                        day_of_week = request.form['day_of_week']
                        existing_schedule = Schedule.query.filter(
                            Schedule.lab_id == lab_id,
                            Schedule.schedule_type == 'day',
                            Schedule.day_of_week == day_of_week,
                            Schedule.start_time < end_time,
                            Schedule.end_time > start_time,
                            Schedule.id != schedule_id
                        ).first()
                        if existing_schedule:
                            flash('Ya existe un horario para este día y franja horaria, existe un cruce de horario', 'warning')
                            return redirect(url_for('manage_schedule'))
                        schedule.lab_id = lab_id
                        schedule.user_id = profe_id
                        schedule.schedule_type = 'day'
                        schedule.day_of_week = day_of_week
                        schedule.date = None
                        schedule.start_time = start_time
                        schedule.end_time = end_time
                    elif schedule_type == 'date':
                        date = request.form['date']
                        existing_schedule_date = Schedule.query.filter(
                            Schedule.lab_id == lab_id,
                            Schedule.schedule_type == 'date',
                            Schedule.date == date,
                            Schedule.start_time < end_time,
                            Schedule.end_time > start_time,
                            Schedule.id != schedule_id
                        ).first()
                        if existing_schedule_date:
                            flash('Ya existe un horario para esta fecha y franja horaria, existe un cruce de horario', 'warning')
                            return redirect(url_for('manage_schedule'))
                        schedule.lab_id = lab_id
                        schedule.user_id = profe_id
                        schedule.schedule_type = 'date'
                        schedule.date = date
                        schedule.day_of_week = None
                        schedule.start_time = start_time
                        schedule.end_time = end_time
                    else:
                        flash('Tipo de agendamiento no válido', 'danger')
                        return redirect(url_for('manage_schedule'))

                    db.session.commit()
                    flash('Horario actualizado exitosamente', 'success')
                else:
                    flash('Horario no encontrado', 'danger')

        # Para que el modal funcione correctamente, pasar todos los usuarios con rol 'profe'
        users = User.query.filter_by(role='profe').all()
        labs = Laboratory.query.all()
        # Cargar los horarios con la relación de usuario asignado (para mostrar el nombre correctamente)
        schedules = Schedule.query.options(db.joinedload(Schedule.assigned_user)).all()
        return render_template('schedule.html', users=users, labs=labs, schedules=schedules)

    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
        return redirect(url_for('manage_schedule'))


# Ruta para ver los registros de acceso (solo usuarios root y admin)
@app.route('/logs')
@login_required
@role_required('root', 'admin')
def view_logs():
    try:
        logs = AccessLog.query.options(
            db.joinedload(AccessLog.user),  # Cargar relación con User
            db.joinedload(AccessLog.lab)
        ).all()
        formatted_logs = [
            {
                "id": log.id,
                "lab_name": log.lab_name,  # Nombre del laboratorio
                "name": log.user.name.capitalize(),  # Nombre de usuario
                "user_id": log.user.qr_code,  # Identificación del usuario
                "role": log.user.role.capitalize(),  # Rol del usuario
                "date": log.timestamp.strftime('%Y-%m-%d'),  # Formato de fecha
                "time": log.timestamp.strftime('%H:%M')  # Formato de hora
            }
            for log in logs
        ]
        return render_template('logs.html', logs=formatted_logs)
    except Exception as e:
        print(e)
        flash(f'Ocurrió un error: {str(e)}', 'danger')
        return redirect(url_for('home'))

# Ruta para eliminar un registro de acceso (solo usuarios root y admin)   
@app.route('/delete_log', methods=['POST'])
@login_required
@role_required('root', 'admin')
def delete_log():
    try:
        log_id = request.form['log_id']
        log = db.session.get(AccessLog, log_id)  # Actualizado a Session.get()
        if log:
            db.session.delete(log)
            db.session.commit()
            flash('Registro eliminado exitosamente', 'success')
        else:
            flash('Registro no encontrado', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    return redirect(url_for('view_logs'))


# Ruta para validar un código QR
@app.route('/qr', methods=['POST'])
def validate_qr():
    try:
        data = request.json
        lab_name = data.get('labID')  # Obtener el nombre del laboratorio
        qr_code = data.get('qr')
        current_time = datetime.now(COLOMBIA_TZ).time()
        current_date = datetime.now(COLOMBIA_TZ).date()

        # Obtener el día de la semana en español
        dias_semana = ['lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado', 'domingo']
        current_day_of_week = dias_semana[current_date.weekday()]

        # Verificar si el usuario existe
        user = User.query.filter_by(qr_code=qr_code).first()
        if not user:
            return jsonify({'status': 'unauthorized', 'labID': lab_name, 'message': 'Código QR inválido'})

        # Verificar si el laboratorio existe
        lab = Laboratory.query.filter_by(name=lab_name).first()
        if not lab:
            return jsonify({'status': 'unauthorized', 'labID': lab_name, 'message': 'Laboratorio no encontrado'})

        # Verificar agendamientos por fecha
        schedule_by_date = Schedule.query.filter(
            Schedule.lab_id == lab.id,
            Schedule.user_id == user.id,
            Schedule.schedule_type == 'date',
            Schedule.date == current_date,
            Schedule.start_time <= current_time,
            Schedule.end_time >= current_time
        ).first()

        # Verificar agendamientos por día de la semana
        schedule_by_day = Schedule.query.filter(
            Schedule.lab_id == lab.id,
            Schedule.user_id == user.id,
            Schedule.schedule_type == 'day',
            Schedule.day_of_week == current_day_of_week,
            Schedule.start_time <= current_time,
            Schedule.end_time >= current_time
        ).first()

        # Validar si existe un horario válido
        if schedule_by_date or schedule_by_day:
            logs = AccessLog(
                user_id=user.id,
                lab_id=lab.id,
                lab_name=lab_name,
                timestamp=datetime.now(COLOMBIA_TZ)
            )
            db.session.add(logs)
            db.session.commit()
            return jsonify({'status': 'success', 'labID': lab_name, 'message': 'Ingreso autorizado'})

        return jsonify({'status': 'unauthorized', 'labID': lab_name, 'message': 'Horario no válido'})
    except Exception as e:
        return jsonify({'status': 'error', 'labID': lab_name, 'message': f'Ocurrió un error: {str(e)}'})


# Ruta para cambiar los detalles de un usuario (solo usuarios root)
@app.route('/change_user_details', methods=['POST'])
@login_required
@role_required('root')
def change_user_details():
    try:
        user_id = request.form['user_id']
        username = request.form['username']
        new_password = request.form['new_password']
        
        user = db.session.get(User, user_id)  # Actualizado a Session.get()
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


# Ruta para subir un horario desde un archivo Excel (solo usuarios root y admin)
@app.route('/upload_schedule', methods=['GET', 'POST'])
@login_required
@role_required('root', 'admin')
def upload_schedule():
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith('.xlsx'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            try:
                # Leer el archivo Excel
                df = pd.read_excel(filepath)

                # Procesar los datos y guardarlos en la base de datos
                for index, row in df.iterrows():
                    lab_name = str(row['Laboratorio'])
                    description = str(row['Descripcion'])
                    name_user = str(row['Nombre'])
                    qr_code = str(row['Identificacion']).rstrip('.0') if not pd.isnull(row['Identificacion']) else None
                    date = row['Fecha']
                    start_time = row['Hora Inicio']
                    end_time = row['Hora Final']

                    # Manejar valores faltantes
                    if lab_name == 'nan':
                        lab_name = 'None'
                        flash(f'Laboratorio no especificado en la fila {index + 1}, se ha asignado "None"', 'warning')
                    if name_user == 'nan':
                        name_user = 'None'
                        flash(f'Nombre del usuario no especificado en la fila {index + 1}, se ha asignado "None"', 'warning')
                    if not qr_code:
                        qr_code = generate_qr_code()  # Generar dinámicamente si no se proporciona
                        flash(f'QR Code generado dinámicamente para {name_user}: {qr_code}', 'info')
                    if pd.isnull(date) or pd.isnull(start_time) or pd.isnull(end_time):
                        flash(f'Fechas u horas no especificadas para el usuario {name_user} en la fila {index + 1}, se ha creado el usuario pero no se ha asignado un horario', 'warning')
                        # Crear el usuario si no existe
                        user = User.query.filter_by(qr_code=qr_code).first()
                        if not user:
                            username = Nombre(name_user)
                            password_hash = generate_password_hash(qr_code)
                            new_user = User(username=username, password_hash=password_hash, role='profe', name=name_user, qr_code=qr_code)
                            db.session.add(new_user)
                            db.session.commit()
                        continue

                    # Convertir la fecha y las horas a cadenas si son objetos Timestamp
                    date_str = date.strftime('%Y-%m-%d') if isinstance(date, pd.Timestamp) else str(date)
                    start_time_str = start_time.strftime('%H:%M:%S') if isinstance(start_time, pd.Timestamp) else str(start_time)
                    end_time_str = end_time.strftime('%H:%M:%S') if isinstance(end_time, pd.Timestamp) else str(end_time)

                    # Convertir las cadenas a los formatos correctos
                    date_converted = datetime.strptime(date_str, '%Y-%m-%d').date()
                    start_time_converted = datetime.strptime(start_time_str, '%H:%M:%S').time()
                    end_time_converted = datetime.strptime(end_time_str, '%H:%M:%S').time()

                    # Verificar si el laboratorio existe
                    lab = Laboratory.query.filter_by(name=lab_name).first()
                    if not lab:
                        lab = Laboratory(name=lab_name, description=description)  # Crear un nuevo laboratorio con descripción
                        db.session.add(lab)
                        db.session.commit()
                        flash(f'Laboratorio {lab_name} no encontrado, se ha creado con la descripcion {description}', 'warning')

                    # Verificar si el usuario existe
                    user = User.query.filter_by(qr_code=qr_code).first()
                    if not user:
                        # Crear un nuevo usuario
                        username = Nombre(name_user)
                        password_hash = generate_password_hash(qr_code)
                        new_user = User(username=username, password_hash=password_hash, role='profe', name=name_user, qr_code=qr_code)
                        db.session.add(new_user)
                        db.session.commit()
                        flash(f'Usuario creado: {name_user} con QR Code: {qr_code}', 'success')

                    # Crear un nuevo horario
                    new_schedule = Schedule(
                        lab_id=lab.id,
                        user_id=user.id,
                        date=date_converted,
                        start_time=start_time_converted,
                        end_time=end_time_converted
                    )
                    db.session.add(new_schedule)
                db.session.commit()
                flash('Horarios cargados exitosamente', 'success')
                os.remove(filepath)  # Eliminar el archivo después de procesarlo
            except Exception as e:
                db.session.rollback()
                flash(f'Ocurrió un error al procesar el archivo: {str(e)}', 'danger')
                os.remove(filepath)  # Asegurarse de eliminar el archivo incluso si ocurre un error
            return redirect(url_for('upload_schedule'))
        else:
            flash('Por favor, suba un archivo Excel válido', 'warning')
    return render_template('upload_schedule.html')


# Ruta para ver el perfil 
@app.route('/profile')
@login_required
def profile():
    user = db.session.get(User, session['user_id'])  # Obtener el usuario actual
    if not user:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('login'))
    return render_template('profile.html', user=user)  # Pasar el objeto 'user' a la plantilla

# Ruta para  cambiar su contraseña
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        try:
            user_id = session['user_id']
            user = db.session.get(User, user_id)
            new_password = request.form['new_password']
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Contraseña actualizada exitosamente', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ocurrió un error: {str(e)}', 'danger')
        return redirect(url_for('profile'))
    return render_template('change_password.html')

# Ruta para que el usuario root cambie la contraseña de un profesor
@app.route('/change_password_root', methods=['POST'])
@login_required
@role_required('root')
def change_password_root():
    try:
        user_id = request.form['user_id']
        new_password = request.form['new_password']
        user = db.session.get(User, user_id)
        if user:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Contraseña actualizada exitosamente', 'success')
        else:
            flash('Usuario no encontrado', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    return redirect(url_for('manage_users'))

# Ruta para actualizar la información del perfil 
@app.route('/update_profile', methods=['POST'])
@login_required
@role_required('root', 'admin', 'profe', 'student')
def update_profile():
    try:
        user_id = session['user_id']
        user = db.session.get(User, user_id)
        user.username = request.form['username']
        user.email = request.form['email']
        if request.form['password']:
            user.password_hash = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('Perfil actualizado exitosamente', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    return redirect(url_for('profile'))

# Ruta para ver los horarios y agendar estudiantes (solo profesores)
@app.route('/my_schedule', methods=['GET', 'POST'])
@login_required
def my_schedule():
    user = db.session.get(User, session['user_id'])
    schedules = Schedule.query.filter_by(user_id=user.id).all()

    # Solo los profesores pueden agendar estudiantes
    students = []
    if user.role == 'profe':
        students = User.query.filter_by(role='student').all()

    return render_template('my_schedule.html', user=user, schedules=schedules, students=students)

# Ruta para ver el carnet del profesor
@app.route('/my_qr')
@login_required
def my_qr():
    user = db.session.get(User, session['user_id'])  # Obtener el usuario actual
    if not user:
        flash('Usuario no encontrado', 'danger')
        return redirect(url_for('login'))
    return render_template('my_qr.html', user=user)  # Pasar el objeto 'user' a la plantilla

# Ruta para gestionar estudiantes (solo usuarios root y admin)
@app.route('/manage_students', methods=['GET', 'POST'])
@login_required
@role_required('root', 'admin')
def manage_students():
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                name = request.form['name']
                qr_code = request.form['qr_code']
                username = Nombre(name)
                password_hash = generate_password_hash(qr_code)
                new_user = User(username=username, password_hash=password_hash, role='student', name=name, qr_code=qr_code)
                db.session.add(new_user)
                db.session.commit()
                flash('Estudiante agregado exitosamente', 'success')
            elif action == 'delete':
                user_id = request.form['user_id']
                user = User.query.get(user_id)
                if user:
                    db.session.delete(user)
                    db.session.commit()
                    flash('Estudiante eliminado exitosamente', 'success')
                else:
                    flash('Estudiante no encontrado', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    students = User.query.filter_by(role='student').all()
    return render_template('students.html', students=students)

# Ruta para gestionar el acceso de estudiantes a laboratorios (solo profesores)
@app.route('/assign_student_access', methods=['GET', 'POST'])
@login_required
@role_required('profe')
def assign_student_access():
    try:
        user = db.session.get(User, session['user_id'])
        schedules = Schedule.query.filter_by(user_id=user.id).all()

        if request.method == 'POST':
            student_id = request.form['student_id']
            schedule_id = request.form['schedule_id']
            access_type = request.form['access_type']

            # Verificar si ya existe un acceso para el estudiante y horario
            existing_access = StudentAccess.query.filter_by(user_id=student_id, schedule_id=schedule_id).first()
            if existing_access:
                flash('El estudiante ya tiene acceso asignado a este horario', 'warning')
                return redirect(url_for('assign_student_access'))

            new_access = StudentAccess(user_id=student_id, schedule_id=schedule_id, access_type=access_type)
            db.session.add(new_access)
            db.session.commit()
            flash('Acceso asignado exitosamente', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    students = User.query.filter_by(role='student').all()
    return render_template('assign_student_access.html', students=students, schedules=schedules)

# Ruta para validar el acceso de estudiantes
@app.route('/validate_student_access', methods=['POST'])
def validate_student_access():
    try:
        data = request.json
        lab_name = data.get('labID')
        qr_code = data.get('qr')
        current_time = datetime.now(COLOMBIA_TZ).time()
        current_date = datetime.now(COLOMBIA_TZ).date()

        # Obtener el día de la semana en español
        dias_semana = ['lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado', 'domingo']
        current_day_of_week = dias_semana[current_date.weekday()]

        # Verificar si el estudiante existe
        student = User.query.filter_by(qr_code=qr_code, role='student').first()
        if not student:
            return jsonify({'status': 'unauthorized', 'labID': lab_name, 'message': 'Código QR inválido'})

        # Verificar si el laboratorio existe
        lab = Laboratory.query.filter_by(name=lab_name).first()
        if not lab:
            return jsonify({'status': 'unauthorized', 'labID': lab_name, 'message': 'Laboratorio no encontrado'})

        # Verificar acceso por horario
        access = StudentAccess.query.join(Schedule).filter(
            StudentAccess.user_id == student.id,
            Schedule.lab_id == lab.id,
            ((Schedule.schedule_type == 'date') & (Schedule.date == current_date)) |
            ((Schedule.schedule_type == 'day') & (Schedule.day_of_week == current_day_of_week)),
            Schedule.start_time <= current_time,
            Schedule.end_time >= current_time
        ).first()

        if not access:
            return jsonify({'status': 'unauthorized', 'labID': lab_name, 'message': 'Acceso no autorizado'})

        # Verificar tipo de acceso
        if access.access_type == 'delegated':
            # Verificar si el profesor ya ingresó
            professor_log = AccessLog.query.filter_by(user_id=access.schedule.user_id, lab_id=lab.id).first()
            if not professor_log:
                return jsonify({'status': 'unauthorized', 'labID': lab_name, 'message': 'El profesor aún no ha ingresado'})

        # Registrar el acceso del estudiante
        logs = AccessLog(
            user_id=access.schedule.user_id,
            lab_id=lab.id,
            lab_name=lab_name,
            timestamp=datetime.now(COLOMBIA_TZ)
        )
        db.session.add(logs)
        db.session.commit()
        return jsonify({'status': 'success', 'labID': lab_name, 'message': 'Ingreso autorizado'})
    except Exception as e:
        return jsonify({'status': 'error', 'labID': lab_name, 'message': f'Ocurrió un error: {str(e)}'})

# RUTA DE EROR 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#RUTA DE ERROR 500
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_initial_user()
       
        app.run(debug=True )
