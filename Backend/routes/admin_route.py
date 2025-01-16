from flask import Blueprint, request, jsonify
from Backend.model.outage import Outage
from Backend.model.user import User
from flask_jwt_extended import jwt_required
from Backend.routes.outage_route import outage_bp
from flask_jwt_extended import jwt_required, get_jwt_identity

admin_bp = Blueprint("admin", __name__)

@outage_bp.route('/update-outage/<outage_id>', methods=['PATCH'])
@jwt_required()
def update_outage_status(outage_id):
    user_id = get_jwt_identity()
    user = User.objects(id=user_id).first()
    
    outage = Outage.objects(id=outage_id).first()
    if not outage:
        return jsonify({"error": "Outage not found"}), 404

    if user.role == "user" and outage.user != user:
        return jsonify({"error": "Unauthorized to update this outage"}), 403
    
    data = request.json
    new_status = data.get('status', None)
    if new_status:
        outage.update(set__status=new_status)  # Update status
        return jsonify({"message": "Outage status updated successfully"}), 200
    return jsonify({"error": "Status field is required"}), 400