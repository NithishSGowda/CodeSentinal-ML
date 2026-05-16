"""
Database Initialization Script
Run this once to create all tables and seed the default admin account.
Usage: python init_db.py
"""

from app import app
from database import db, User


def init():
    with app.app_context():
        print("[*] Creating all database tables...")
        db.create_all()
        print("[+] Tables created.")

        # Create default admin
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@forensiq.local",
                role="admin",
                full_name="System Administrator",
                badge_number="ADM-001",
                department="Cyber Forensics Division",
            )
            admin.set_password("Admin@ForensIQ2024")
            db.session.add(admin)
            db.session.commit()
            print("[+] Default admin created:")
            print("    Username : admin")
            print("    Password : Admin@ForensIQ2024")
            print("    Role     : admin")
        else:
            print("[=] Admin account already exists.")

        print("\n[OK] Database initialization complete!")
        print("[OK] Run: python app.py  to start the server.")


if __name__ == "__main__":
    init()
