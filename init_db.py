from qr_access_system.app import app, db
from qr_access_system import create_initial_user  # Adjust the import path as necessary

with app.app_context():
    db.create_all()
    create_initial_user()
