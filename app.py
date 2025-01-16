from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify
from flask_jwt_extended import JWTManager
from Backend.db_connection import init_db_connection
from Backend.routes.auth_user import auth_bp
from Backend.routes.outage_route import outage_bp
from Backend.routes.admin_route import admin_bp
from flask import Flask, send_from_directory
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import check_password_hash, generate_password_hash
from Backend.model.user import User
from Backend.model.outage import Outage
from datetime import datetime, timedelta
import os



app = Flask(__name__, template_folder="Frontend/templates", static_folder="Frontend/static" )
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "JjQg63PgKbr1ac,dFF246810")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.secret_key = os.getenv("SECRET_KEY", "r!ac,iED$su2@3458994")



@app.route('/')
def home():
    return render_template('homepage.html')

# Initialize extensions
jwt = JWTManager(app)
init_db_connection(DB="power_outage_db",  URI='mongodb://127.0.0.1:27017')

# Register blueprints
app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(outage_bp, url_prefix="/outage")
app.register_blueprint(admin_bp, url_prefix="/admin")

@app.route("/select_role", methods=["GET", "POST"])
def select_role():
    if request.method == "POST":
        role = request.form.get("role")  # Get the selected role (user/admin)
        action = request.form.get("action")  # Get the action (signup/signin)

        if role == "user" and action == "signup":
            return redirect("/register/user")  # Redirect to user registration
        elif role == "user" and action == "signin":
            return redirect("/login/user")  # Redirect to user login
        elif role == "admin" and action == "signup":
            return redirect("/register/admin")  # Redirect to admin registration
        elif role == "admin" and action == "signin":
            return redirect("/login/admin")  # Redirect to admin login
        else:
            flash("Invalid selection. Please try again.")
            return redirect("/select_role")

    return render_template("role.html")  # Render the page for GET requests

        
@app.route("/login/user", methods=["GET", "POST"])
def login_user():
    if "user_id" in session:  # Check if the user is already logged in
        return redirect("/dashboard")  # Redirect to the dashboard or home

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.objects(email=email, role="user").first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = str(user.id)  # Store user session ID
            session["role"] = "user"  # Set the role as 'user'
            flash("User Login Successful")
            return redirect("/dashboard")  # Redirect to home or dashboard
        else:
            flash("Invalid email or password")
    return render_template("UserLogin.html")


@app.route("/login/admin", methods=["GET", "POST"])
def login_admin():
    if "user_id" in session:  # Check if the user is already logged in
        return redirect("/dashboard")  # Redirect to the dashboard or home

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        adminpin = request.form["adminpin"]

        user = User.objects(email=email, role="admin").first()

        if user and check_password_hash(user.password, password) and user.adminpin == adminpin:
            session["user_id"] = str(user.id)  # Store user session ID
            session["role"] = "admin"  # Set the role as 'admin'
            flash("Admin Login Successful")
            return redirect("/dashboard")  # Redirect to admin dashboard
        else:
            flash("Invalid credentials")
    return render_template("AdminLogin.html")


@app.route("/register/user", methods=["GET", "POST"])
def register_user():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        location = request.form["location"]
        phone = request.form["phone"]
        password = generate_password_hash(request.form["password"])

        # Check if the user already exists
        if User.objects(email=email).first():
            flash("User with this email already exists.")
            return redirect("/register/user")

        user = User(
            name=name,
            email=email,
            location=location,
            phone=phone,
            password=password,
            role="user",
        )
        user.save()
        flash("User registered successfully!")
        print("Redirecting to login page")
        return redirect("/login/user")
    return render_template("UserRegistration.html")

# Admin registration route
@app.route("/register/admin", methods=["GET", "POST"])
def register_admin():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        location = request.form["location"]
        phone = request.form["phone"]
        password = generate_password_hash(request.form["password"])
        adminpin = request.form["adminpin"]

        # Check if the admin already exists
        if User.objects(email=email).first():
            flash("Admin with this email already exists.")
            return redirect("/register/admin")

        admin = User(
            name=name,
            email=email,
            location=location,
            phone=phone,
            password=password,
            adminpin=adminpin,
            role="admin",
        )
        admin.save()
        flash("Admin registered successfully!")
        return redirect("/login/admin")
    return render_template("AdminRegistration.html")


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    role = session.get('role')  # Get role from session, it should now be set correctly
    user_name = session.get('user_name', 'Guest')  # Get user_name from session, default to 'Guest'

    if not role:  # If role is not set in session, redirect to the login page
        return redirect('/login/admin' if 'admin' in request.url else '/login/user')

    # Render the dashboard with the appropriate role-based content
    return render_template('dashboard.html', role=role, user_name=user_name)



@app.route('/view_profile', methods=['GET'])
def view_profile():
    user_id = session.get('user_id')  # Use session data instead of JWT
    if not user_id:
        return redirect('/login/user')  # Redirect to login if the user is not authenticated

    user = User.objects(id=user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return render_template('profile.html', user=user)


@app.route('/make_report', methods=['GET', 'POST'])
##@jwt_required()  # Require JWT token for authentication
def make_report():
    user_id = session.get('user_id')  # Get the authenticated user's ID from the JWT token
    user = User.objects(id=user_id).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == 'GET':
        # Render the outage report form for users
        return render_template("Outages_reports.html")

    if user.role != "user":
        # Only users are authorized to make outage reports
        flash("Only regular users can submit outage reports.", "error")
        return redirect('/dashboard')

    # Handle form data submission
    description = request.form.get('description')
    location = request.form.get('location')
    status = request.form.get('status', 'pending')  # Default to 'pending' if not provided

    # Validate the inputs
    if not description or not location:
        flash("All fields are required to submit a report.", "error")
        return redirect('/make_report')

    # Ensure the status is valid
    if status not in ["pending", "in-progress", "resolved"]:
        flash("Invalid status value.", "error")
        return redirect('/make_report')

    # Create and save the outage report
    outage = Outage(
        user=user,
        description=description,
        location=location,
        status=status,
        timestamp=datetime.now  # Record the submission time
    )
    outage.save()

    flash("Your report has been successfully submitted!", "success")
    return redirect('/dashboard')


@app.route('/view_reports', methods=['GET'])

def view_reports():
    user_id = session.get('user_id')
    user = User.objects(id=user_id).first()

    reports = Outage.objects(user=user)
    return render_template('user_reports.html', reports=reports, user=user)


@app.route('/view_all_reports', methods=['GET'])
def view_all_reports():
    user_id = session.get('user_id')
    user = User.objects(id=user_id).first()

    if user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    reports = Outage.objects()
    return render_template('admin_reports.html', reports=reports)


@app.route('/update_reports', methods=['GET', 'POST', 'PATCH'])
def update_reports():
    user_id = session.get('user_id')
    user = User.objects(id=user_id).first()

    # Ensure only admin can access this route
    if not user or user.role != "admin":
        print(user.role)
        return jsonify({"error": "Unauthorized"}), 403

    # Handle GET request to render the template
    if request.method == 'GET':
        reports = Outage.objects.all()
        return render_template('admin_update.html', reports=reports)

    # Handle POST request to update multiple reports from the form
    if request.method == 'POST':
        updated_reports = []
        for report_id, new_status in request.form.items():
            if report_id.startswith('status_'):  # Identify status fields
                report_id = report_id.replace('status_', '')
                report = Outage.objects(id=report_id).first()
                if report and new_status:
                    report.update(set__status=new_status, set__timestamp=datetime.now())
                    updated_reports.append(report_id)

        return redirect(url_for('dashboard'))

    # Handle PATCH request for single report updates (API-style)
    if request.method == 'PATCH':
        report_id = request.json.get('report_id')
        new_status = request.json.get('status')
        report = Outage.objects(id=report_id).first()

        if not report:
            return jsonify({"error": "Report not found"}), 404
        if new_status:
            report.update(set__status=new_status, set__timestamp=datetime.now())
            return jsonify({"message": "Report updated successfully"}), 200

        return jsonify({"error": "Status field is required"}), 400


@app.route('/logout', methods=["GET"])
def logout():
    # Clear all session data to log out the user
    session.clear()
    flash("You have been successfully logged out.", "success")
    if 'role' in session and session['role'] == 'admin':
        return redirect(url_for('home'))  # Admin login
    else:
        return redirect(url_for('home'))  # User login



if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0')