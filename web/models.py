from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    token = db.Column(db.String(120), unique=True, nullable=True)
    subscription_plan = db.Column(db.String(20), default='trial')  # trial, individual, family, small_team
    subscription_status = db.Column(db.String(20), default='inactive')  # inactive, active, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    devices = db.relationship('Device', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'
    
    def generate_token(self):
        """Generate a unique token for the user"""
        self.token = str(uuid.uuid4())
        db.session.commit()
        return self.token

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    platform = db.Column(db.String(20), nullable=False)  # windows, mac, linux, android, ios
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    config = db.Column(db.Text, nullable=True)  # WireGuard configuration
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Device {self.name} on {self.platform}>'