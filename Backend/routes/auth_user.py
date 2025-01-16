from flask import Blueprint, request, jsonify
from Backend.model.user import User
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
import sys
import os

# Add the Backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))


auth_bp = Blueprint("auth", __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = generate_password_hash(data['password'])
    user = User(
        name=data['name'],
        email=data['email'],
        phone=data.get('phone', ''),
        location=data['location'],
        password=hashed_password,
    )
    user.save()
    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.objects(email=data['email']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({"token": token, "message":"successfully login"}), 200