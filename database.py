from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    target_date = db.Column(db.DateTime)
    priority = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='pending')
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship('Category', backref='tasks')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(7), default='#000000')  # Hex color code

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100))
    password_hash = db.Column(db.String(200))  # For storing hashed passwords
    google_id = db.Column(db.String(100))
    profile_pic = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationship with tasks
    tasks = db.relationship('Task', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def get_or_create(google_data):
        user = User.query.filter_by(google_id=google_data['sub']).first()
        if not user:
            user = User(
                google_id=google_data['sub'],
                name=google_data['name'],
                email=google_data['email'],
                profile_pic=google_data.get('picture')
            )
            db.session.add(user)
            db.session.commit()
        user.last_login = datetime.utcnow()
        db.session.commit()
        return user