from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from database import db, Task, Category, User
from datetime import datetime, timezone
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
import logging
import os.path

logging.basicConfig(level=logging.DEBUG)
# Load environment variables
load_dotenv()

# Update the database path configuration
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'tasks.db')

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "SECRET_KEY"

# Initialize extensions
db.init_app(app)

# Initialize database if it doesn't exist
if not os.path.exists(db_path):
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# OAuth setup
oauth = OAuth(app)
oauth.register(
    name="google",
    client_id="GOOGLE_CLIENT_ID",
    client_secret="GOOGLE_CLIENT_SECRET",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
    },
)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Auth routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Please enter both email and password", "error")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            flash(f"Welcome back, {user.name}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password", "error")
        return redirect(url_for("login"))

    return render_template("auth/login.html")


@app.route("/login/google")
def google_login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    redirect_uri = url_for("google_auth", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/google")
def google_auth():
    try:
        token = oauth.google.authorize_access_token()
        resp = oauth.google.get("https://www.googleapis.com/oauth2/v3/userinfo")
        user_info = resp.json()

        # Check if user exists
        user = User.query.filter_by(email=user_info["email"]).first()

        if not user:
            # Create new user
            user = User(
                name=user_info["name"],
                email=user_info["email"],
                google_id=user_info["sub"],
                profile_pic=user_info.get("picture"),
            )
            db.session.add(user)
            db.session.commit()

        # Update last login
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        # Log in user
        login_user(user)
        flash(f"Welcome, {user.name}!", "success")

        # Redirect to main page
        return redirect(url_for("dashboard"))

    except Exception as e:
        print(f"Error in google_auth: {str(e)}")  # For debugging
        flash("Failed to log in with Google.", "error")
        return redirect(url_for("login"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# Task routes - all protected
@app.route("/")
def landing():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/dashboard")
@login_required
def dashboard():
    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .order_by(Task.created_at.desc())
        .all()
    )
    return render_template("index.html", tasks=tasks)


@app.route("/detailed")
@login_required
def detailed_index():
    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .order_by(Task.created_at.desc())
        .all()
    )
    return render_template("detailed_index.html", tasks=tasks)


@app.route("/tasks", methods=["POST"])
@login_required
def add_task():
    title = request.form.get("title")
    if title:
        task = Task(title=title, user_id=current_user.id)
        db.session.add(task)
        db.session.commit()
    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .order_by(Task.created_at.desc())
        .all()
    )
    return render_template("partials/task_list.html", tasks=tasks)


@app.route("/detailed/tasks", methods=["POST"])
@login_required
def add_detailed_task():
    title = request.form.get("title")
    target_date = request.form.get("target_date")
    priority = request.form.get("priority", 0)
    status = request.form.get("status", "pending")

    if title:
        task = Task(
            title=title,
            target_date=(
                datetime.strptime(target_date, "%Y-%m-%d") if target_date else None
            ),
            priority=priority,
            status=status,
            user_id=current_user.id,
        )
        db.session.add(task)
        db.session.commit()

    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .order_by(Task.created_at.desc())
        .all()
    )
    return render_template("partials/task_list_with_status.html", tasks=tasks)


@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return "Unauthorized", 403
    task.completed = not task.completed
    db.session.commit()
    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .order_by(Task.created_at.desc())
        .all()
    )
    return render_template("partials/task_list.html", tasks=tasks)


@app.route("/tasks/<int:task_id>/delete", methods=["DELETE"])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return "Unauthorized", 403
    db.session.delete(task)
    db.session.commit()
    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .order_by(Task.created_at.desc())
        .all()
    )
    return render_template("partials/task_list.html", tasks=tasks)


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return "Unauthorized", 403

    if request.method == "POST":
        task.title = request.form.get("title")
        if request.form.get("target_date"):
            task.target_date = datetime.strptime(
                request.form.get("target_date"), "%Y-%m-%d"
            )
        task.priority = int(request.form.get("priority", 0))
        task.status = request.form.get("status", "pending")
        db.session.commit()
        return render_template("partials/task_list_with_status.html", tasks=[task])

    return render_template("partials/edit_task.html", task=task)


@app.route("/tasks/today")
@login_required
def today_tasks():
    today = datetime.now(timezone.utc).date()
    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .filter(db.func.date(Task.target_date) == today)
        .order_by(Task.priority.desc())
        .all()
    )
    return render_template("partials/task_list_with_status.html", tasks=tasks)


@app.route("/tasks/upcoming")
@login_required
def upcoming_tasks():
    today = datetime.now(timezone.utc).date()
    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .filter(Task.target_date > today)
        .order_by(Task.target_date.asc())
        .all()
    )
    return render_template("partials/task_list_with_status.html", tasks=tasks)


@app.route("/tasks/priority")
@login_required
def priority_tasks():
    tasks = (
        Task.query.filter_by(user_id=current_user.id)
        .filter(Task.priority > 0)
        .order_by(Task.priority.desc())
        .all()
    )
    return render_template("partials/task_list_with_status.html", tasks=tasks)


# Category routes
@app.route("/categories/manage")
@login_required
def manage_categories():
    return render_template(
        "partials/manage_categories.html", categories=Category.query.all()
    )


@app.route("/categories/add", methods=["POST"])
@login_required
def add_category():
    name = request.form.get("name")
    color = request.form.get("color", "#000000")
    if name:
        category = Category(name=name, color=color)
        db.session.add(category)
        db.session.commit()
    return render_template("partials/sidebar.html")


@app.route("/categories/<int:category_id>/delete", methods=["DELETE"])
@login_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    return render_template("partials/sidebar.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")

        if not email or not name or not password:
            flash("Please fill in all fields", "error")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered", "error")
            return redirect(url_for("signup"))

        user = User(email=email, name=name)
        user.set_password(password)
        user.created_at = datetime.now(timezone.utc)

        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("auth/signup.html")


if __name__ == "__main__":
    app.run(debug=False)
