"""Create calendar.db and the default admin account.

Run once:  python create_db.py
Default login ->  username: admin   password: Admin@12345
(override with env vars ADMIN_USER / ADMIN_PASSWORD; change it after first login)
"""
import app  # importing app runs init_db()

print("Database ready:", app.DB_PATH)
print("Admin username:", app.ADMIN_USER)
print("Admin password:", app.ADMIN_PASS)