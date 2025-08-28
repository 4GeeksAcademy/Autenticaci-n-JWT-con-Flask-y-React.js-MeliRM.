from __future__ import annotations
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os


app = Flask(__name__, static_folder="../web", static_url_path="/")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
Migrate(app, db)


class User(db.Model):
    __tablename__ = "users"
    id = db.mapped_column(db.Integer, primary_key=True)
    email = db.mapped_column(db.String(120), unique=True, nullable=False)
    password_hash = db.mapped_column(db.String(255), nullable=False)
    is_active = db.mapped_column(db.Boolean, nullable=False, default=True)


@app.get("/api/health")
def health():
    return jsonify({"ok": True})

@app.post("/api/signup")
def signup():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"msg": "email y password son obligatorios"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "email ya registrado"}), 409
    u = User(email=email, password_hash=generate_password_hash(password))
    db.session.add(u); db.session.commit()
    return jsonify({"msg": "usuario creado"}), 201

@app.post("/api/token")
def token():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    u = User.query.filter_by(email=email).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify({"msg": "credenciales inválidas"}), 401
    return jsonify({"access_token": f"token-{u.id}"}), 200

@app.get("/api/private")
def private():
    
    return jsonify({"msg": "OK: contenido privado"}), 200


_HTML = "index.html"
@app.get("/")
@app.get("/signup")
@app.get("/login")
@app.get("/private")
def index():
    return send_from_directory(app.static_folder, _HTML)

if __name__ == "__main__":
    
    if not os.path.exists("app.db"):
        with app.app_context():
            db.create_all()
    app.run(host="0.0.0.0", port=3001, debug=True)
