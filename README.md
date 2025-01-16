# Power Outage Reporter

## Introduction

Power Outage Reporter is a web-based application designed to allow users to report, view, and manage power outages in their areas. The app provides separate roles for users and administrators. Users can report outages, view their reports, and track the status of ongoing or resolved outages. Administrators have additional privileges to manage and update the status of all power outage reports.

This application leverages the Flask framework for building the web application and MongoDB for data storage. The app implements user authentication with JWT (JSON Web Tokens) for secure access and management of power outage reports.

## Features

- **User Authentication**: Supports both user and admin authentication with hashed password storage and admin PIN validation for administrators.
- **Role-Based Access**: Separate interfaces and functionalities for regular users and administrators.
- **Power Outage Reporting**: Users can submit power outage reports specifying the description, location, and status of the outage.
- **Report Management**: Admins can view and update the status of all reported outages.

- **Session Management**: Users and admins are authenticated via sessions for secure access to the platform.

- **Power Outage Tracking**: Users can track the status of their reports (pending, in-progress, resolved).

## Usage

### Setting Up the Project

1. Clone the repository:
    ```bash
    git clone https://github.com/Frimpongrijkaard/power_outage_reporter.git
    cd power_outage_reporter
    ```

2. Create a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # For Linux/macOS
    venv\Scripts\activate  # For Windows
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Configure the environment variables:
    - Set the `JWT_SECRET_KEY` and `SECRET_KEY` in your environment, or specify them in a `.env` file.
    - Ensure you have MongoDB running locally or configure it to connect to a remote instance.

5. Run the application:
    ```bash
    flask run
    ```

6. Access the application in your browser at [http://127.0.0.1:5000](http://127.0.0.1:5000).

### Roles and Permissions

- **User**: Regular users can sign up, log in, submit outage reports, and view their reports.

- **Admin**: Admins have the ability to view and update all outage reports and manage the application as a whole.

### Routes

- **Home page** (`/`): Displays the homepage of the application.
- **Role selection** (`/select_role`): Allows users to select their role (user or admin) and navigate to login or registration.
- **User registration** (`/register/user`): Allows users to register an account.
- **Admin registration** (`/register/admin`): Allows admins to register an account.
- **User login** (`/login/user`): Allows users to log in.
- **Admin login** (`/login/admin`): Allows admins to log in.
- **Dashboard** (`/dashboard`): Displays the dashboard where users can view and manage their reports.
- **Report creation** (`/make_report`): Allows users to create power outage reports.
- **View reports** (`/view_reports`): Displays all outage reports created by the user.
- **Admin view all reports** (`/view_all_reports`): Allows admins to view all power outage reports.
- **Admin report management** (`/update_reports`): Allows admins to update the status of outage reports.
- **Logout** (`/logout`): Logs out the current user or admin.

## Dependencies

The project uses the following dependencies:

- **Flask**: A micro web framework for Python.
- **Flask-JWT-Extended**: Extension to manage JWT-based authentication.
- **Flask-Werkzeug**: A comprehensive WSGI utility library for Python.
- **Flask-Session**: Extension for server-side session management.
- **MongoDB**: A NoSQL database used to store the outage reports.
- **python-dotenv**: For loading environment variables from a `.env` file.
- **Flask-Bcrypt**: For hashing and verifying passwords securely.
- **Flask-PyMongo**: To interact with MongoDB from Flask.
- **pymongo**: The official MongoDB driver for Python.

To install the dependencies, run:
```bash
pip install -r requirements.txt
