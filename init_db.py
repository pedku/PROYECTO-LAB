from qr_access_system.app import app, db, create_initial_user
from flask_migrate import upgrade

with app.app_context():
    db.create_all()
    create_initial_user()
    #upgrade()