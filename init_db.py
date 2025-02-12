from qr_access_system.app import app, db, create_initial_user

with app.app_context():
    db.create_all()
    create_initial_user()
