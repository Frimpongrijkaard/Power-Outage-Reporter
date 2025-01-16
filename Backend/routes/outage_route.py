from flask import Blueprint, request, jsonify
from Backend.model.outage import Outage
from Backend.model.user import User
from flask_jwt_extended import jwt_required, get_jwt_identity

outage_bp = Blueprint("outage", __name__)

@outage_bp.route('/report-outage', methods=['POST'])
@jwt_required()
def report_outage():
    user_id = get_jwt_identity()
    user = User.objects(id=user_id).first()

    if user.role != "user":
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json

    outage = Outage(
        user=user,
        description=data['description'],
        location=data['location']
    )
    outage.save()
    return jsonify({"message": "Outage reported successfully"}), 201

@outage_bp.route('/outages', methods=['GET'])
@jwt_required()
def get_outages():
    user_id = get_jwt_identity()
    user = User.objects(id=user_id).first()
    
    # Admins can view all outages, regular users only their own
    if user.role == "admin":
        outages = Outage.objects()
    else:
        outages = Outage.objects(user=user)

    return jsonify([{
        "id": str(outage.id),
        "location": outage.location,
        "description": outage.description,
        "status": outage.status,
        "timestamp": outage.timestamp.isoformat()
    } for outage in outages]), 200