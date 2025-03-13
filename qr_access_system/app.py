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
#app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv( 'DATABASE_URL', 'postgresql://postgres:Pc200172@localhost/laboratorios_db')
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


# Modelo para los profesores
class Profe(db.Model):
    __tablename__ = 'profes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Añadir campo para el nombre
    qr_code = db.Column(db.String(200), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)  # Relación con la tabla User
    user = db.relationship('User', backref=db.backref('profesor', uselist=False, cascade='all, delete-orphan', overlaps="usuario"), overlaps="usuario")

# Modelo de usuario    
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'root', 'admin', 'viewer', 'profe'	
    profe = db.relationship('Profe', backref='usuario', uselist=False, cascade='all, delete-orphan', overlaps="profesor,user")

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
    profe_id = db.Column(db.Integer, db.ForeignKey('profes.id', ondelete='CASCADE'), nullable=False)
    professor = db.relationship('Profe', backref=db.backref('schedules', cascade='all, delete-orphan'))
    lab = db.relationship('Laboratory', backref=db.backref('schedules', cascade='all, delete-orphan'))
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)

# Modelo para los registros de acceso
class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    id = db.Column(db.Integer, primary_key=True)
    profe_id = db.Column(db.Integer, db.ForeignKey('profes.id', ondelete='CASCADE'), nullable=False)
    lab_id = db.Column(db.Integer, db.ForeignKey('laboratories.id', ondelete='CASCADE'), nullable=False)
    lab_name = db.Column(db.String(100), nullable=False)  # Nueva columna para almacenar el nombre del laboratorio
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(COLOMBIA_TZ))
    professor = db.relationship('Profe', backref=db.backref('access_logs', cascade='all, delete-orphan'))
    lab = db.relationship('Laboratory', backref=db.backref('access_logs', cascade='all, delete-orphan'))

# Crear usuario inicial
def create_initial_user():
    if not User.query.filter_by(username='@root').first():
        password_hash = generate_password_hash('1234')
        root_user = User(username='@root', password_hash=password_hash, role='root')
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
    #gestion de laboratorios para usuarios root y admin
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
    #se visualizan los horarios de los laboratorios en usuario viewer
    if 'role' in session and session['role'] in ['viewer']:
        labs = Laboratory.query.all()
        return render_template('labs.html', labs=labs)
    else:
        flash('Unauthorized access' , 'danger')
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

# Ruta para gestionar usuarios (solo usuarios root)
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('root')
def manage_users():
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            #agrega nuevo usuario
            if action == 'add':
                name = request.form['name']
                qr_code = request.form['identificacion']
                role = request.form['role']
                
                username=Nombre(name)
                password_hash = generate_password_hash(qr_code)
                new_user = User(username=username, password_hash=password_hash, role=role)
                db.session.add(new_user)
                db.session.commit()  # Commit para obtener el ID del nuevo usuario
                
                #se crea un profesor si el nuevo usuario tiene role profe
                if role == 'profe':   
                    new_profe = Profe(name=name, qr_code=qr_code, user_id=new_user.id)
                    db.session.add(new_profe)
                    db.session.commit() 
                flash('Usuario agregado exitosamente', 'success')
                
            # edita usuarios existentes   
            elif action == 'edit':
                user_id = request.form['user_id']
                user = User.query.get(user_id)
                if user:
                    user.username = request.form['username']
                    if user.role == 'profe':
                        profe = Profe.query.filter_by(user_id=user_id).first()
                        if profe:
                            profe.name = request.form['name']
                            profe.qr_code = request.form['qr_code']
                    db.session.commit()
                    flash('Usuario actualizado exitosamente', 'success')
                else:
                    flash('Usuario no encontrado', 'danger')
            #Borrar usuario existente seleccionado       
            elif action == 'delete':
                user_id = request.form['user_id']
                #No SE PERMITE BORRAR EL USUARIO @ROOT
                if user_id == '1':
                    flash('No puedes eliminar el usuario root', 'warning')
                    return redirect(url_for('manage_users'))
                user = User.query.get(user_id)
                if user:
                    # Eliminar primero las referencias en la tabla profes
                    profe = Profe.query.filter_by(user_id=user_id).first()
                    if profe:
                        db.session.delete(profe)
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

# Ruta para gestionar profesores (solo usuarios root y admin)
@app.route('/manage_profe', methods=['GET', 'POST'])
@login_required
@role_required('root', 'admin')
def manage_profe():
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add':
                name_profe = request.form['name']
                qr_code = request.form['qr_code']

                profe = Profe.query.filter_by(qr_code=qr_code).first()
                if not profe:
                    # Crear un nuevo profesor y usuario
                    username = Nombre (name_profe)

                    password_hash = generate_password_hash(qr_code)
                    new_user = User(username=username, password_hash=password_hash, role='profe')
                    db.session.add(new_user)
                    db.session.commit()

                    profe = Profe(name=name_profe, qr_code=qr_code, user_id=new_user.id)
                    db.session.add(profe)
                    db.session.commit()
                flash('Usuario agregado exitosamente', 'success')
            elif action == 'delete':
                user_id = request.form['user_id']
                profe = Profe.query.filter_by(id=user_id).first()
                if profe:
                    # Eliminar primero las referencias en la tabla schedules y access_logs
                    Schedule.query.filter_by(profe_id=profe.id).delete()
                    AccessLog.query.filter_by(profe_id=profe.id).delete()
                    db.session.delete(profe)
                    db.session.commit()

                user = User.query.get(profe.user_id)                    
                if user:
                        db.session.delete(user)
                db.session.commit()
                
                flash('Operación exitosa', 'success')
            return redirect(url_for('manage_profe'))
    except Exception as e:
        db.session.rollback()
        flash(f'Ocurrió un error: {str(e)}', 'danger')
    profes = Profe.query.all()
    return render_template('manage_users.html', profes=profes)

# Ruta para editar un profesor (solo usuarios root y admin)
@app.route('/edit_user', methods=['POST'])
@login_required
@role_required('root', 'admin')
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
                flash('Horario AGREGADO', 'success')
            elif action == 'delete':
               schedule_id = request.form['schedule_id']
               Schedule.query.filter_by(id=schedule_id).delete()
               db.session.commit()
               flash('Horario Eliminado Exitosamente', 'success')
            elif action == 'edit':
                lab_id = request.form['lab_id']
                profe_id = request.form['profe_id']
                date = request.form['date']
                start_time = request.form['start_time']
                end_time = request.form['end_time']
                date_converted = datetime.strptime(date, '%Y-%m-%d').date()
                schedule_id = request.form['schedule_id']
                schedule = db.session.get(Schedule, schedule_id)

                # Verificar si el profesor ya está asignado a una clase en el mismo horario
                existing_schedule = Schedule.query.filter(
                    Schedule.profe_id == profe_id,
                    Schedule.date == date,
                    Schedule.start_time < end_time,
                    Schedule.end_time > start_time,
                    Schedule.id != schedule_id  # Excluir el horario actual
                ).first()

                # Verificar si el laboratorio ya está asignado a una clase en el mismo horario
                existing_schedule_lab = Schedule.query.filter(
                    Schedule.lab_id == lab_id,
                    Schedule.date == date,
                    Schedule.start_time < end_time,
                    Schedule.end_time > start_time,
                    Schedule.id != schedule_id  # Excluir el horario actual
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

                # Actualizar el horario en la base de datos
                schedule.lab_id = lab_id
                schedule.profe_id = profe_id
                schedule.date = date
                schedule.start_time = start_time
                schedule.end_time = end_time
                db.session.commit()
                flash('Schedule updated successfully', 'success')
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}', 'danger')
    labs = Laboratory.query.all()
    profes = Profe.query.all()
    schedules = Schedule.query.all()
    return render_template('schedule.html', labs=labs, profes=profes, schedules=schedules)


# Ruta para ver los registros de acceso (solo usuarios root y admin)
@app.route('/logs')
@login_required
@role_required('root', 'admin')
def view_logs():
    try:
        logs = AccessLog.query.options(
            db.joinedload(AccessLog.professor),
            db.joinedload(AccessLog.lab)
        ).all()
        return render_template('logs.html', logs=logs)
    except Exception as e:
        print(e)
        flash(f'An error occurred: {str(e)}', 'danger')
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
            logs = AccessLog(profe_id=profe.id, lab_id=schedule.lab_id, lab_name=lab_name, timestamp=datetime.now(COLOMBIA_TZ).strftime('%Y-%m-%d %H:%M'))
            db.session.add(logs)
            db.session.commit()
            return jsonify({'status': 'success', 'labID': lab_name})
        else:
            print("No valid schedule found")
            return jsonify({'status': 'unauthorized', 'message': 'No valid schedule found'})
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'})


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
                    name_profe = str(row['Nombre'])
                    qr_code = str(row['Identificacion'])
                    date = row['Fecha']
                    start_time = row['Hora Inicio']
                    end_time = row['Hora Final']

                    # Manejar valores faltantes
                    if lab_name == 'nan':
                        lab_name = 'None'
                        flash(f'Laboratorio no especificado en la fila {index + 1}, se ha asignado "None"', 'warning')
                    if name_profe == 'nan':
                        name_profe = 'None'
                        flash(f'Nombre del profesor no especificado en la fila {index + 1}, se ha asignado "None"', 'warning')
                    if qr_code == 'nan':
                        qr_code = '0123456789'
                        flash(f'Identificación no especificada para el profesor {name_profe} en la fila {index + 1}, se ha asignado "0123456789"', 'warning')
                    if pd.isnull(date) or pd.isnull(start_time) or pd.isnull(end_time):
                        flash(f'Fechas u horas no especificadas para el profesor {name_profe} en la fila {index + 1}, se ha creado el usuario pero no se ha asignado un horario', 'warning')
                        # Crear el usuario y profesor si no existen
                        profe = Profe.query.filter_by(qr_code=qr_code).first()
                        if not profe:
                            username = Nombre(name_profe)
                            password_hash = generate_password_hash(qr_code)
                            new_user = User(username=username, password_hash=password_hash, role='profe')
                            db.session.add(new_user)
                            db.session.commit()

                            profe = Profe(name=name_profe, qr_code=qr_code, user_id=new_user.id)
                            db.session.add(profe)
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

                    # Verificar si el profesor existe
                    profe = Profe.query.filter_by(qr_code=qr_code).first()
                    if not profe:
                        # Crear un nuevo profesor y usuario
                        username = Nombre(name_profe)
                        password_hash = generate_password_hash(qr_code)
                        new_user = User(username=username, password_hash=password_hash, role='profe')
                        db.session.add(new_user)
                        db.session.commit()

                        profe = Profe(name=name_profe, qr_code=qr_code, user_id=new_user.id)
                        db.session.add(profe)
                        db.session.commit()
                   
                        flash(f'Identificacion {qr_code} no encontrada, se ha creado un profesor con nombre "{name_profe}" y usuario "{username}"', 'warning')

                    # Crear un nuevo horario
                    new_schedule = Schedule(
                        lab_id=lab.id,
                        profe_id=profe.id,
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
                print(e)
                os.remove(filepath)  # Asegurarse de eliminar el archivo incluso si ocurre un error
            return redirect(url_for('upload_schedule'))
        else:
            flash('Por favor, suba un archivo Excel válido', 'warning')
    return render_template('upload_schedule.html')


# Ruta para ver el perfil del profesor
@app.route('/profile')
@login_required
@role_required('profe')
def profile():
    user = db.session.get(User, session['user_id'])
    profe = Profe.query.filter_by(user_id=user.id).first()
    return render_template('profile.html', user=user, profe=profe)

# Ruta para que el profesor cambie su contraseña
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@role_required('profe')
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

# Ruta para actualizar la información del perfil del profesor
@app.route('/update_profile', methods=['POST'])
@login_required
@role_required('root', 'admin', 'profe')
def update_profile():
    try:
        user_id = session['user_id']
        user = db.session.get(Profe, user_id)
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

# Ruta para ver los horarios del profesor
@app.route('/my_schedule')
@login_required
@role_required('profe')
def my_schedule():
    user = db.session.get(User, session['user_id'])
    profe = Profe.query.filter_by(user_id=user.id).first()
    schedules = Schedule.query.filter_by(profe_id=profe.id).all()
    return render_template('my_schedule.html', schedules=schedules)

# Ruta para ver el carnet del profesor
@app.route('/my_qr')
@login_required
@role_required('profe')
def my_qr():
    user = db.session.get(User, session['user_id'])
    profe = Profe.query.filter_by(user_id=user.id).first()
    return render_template('my_qr.html', user=user, profe=profe)

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
       
        app.run(debug=False )
