from qr_access_system.app import app, db

with app.app_context():
    db.create_all()
    create_initial_user()
