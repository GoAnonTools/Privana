# This is a simplified version. In production, you would use a proper email service.
from flask import current_app
from flask_mail import Message
from . import mail

def send_confirmation_email(user_email, token):
    # Note: We're not actually sending an email in this example.
    # In a real application, you would use Flask-Mail or another email service.
    # For now, we'll just print the confirmation link.
    confirmation_link = f"http://localhost:5000/confirm/{token}"
    print(f"Confirmation link: {confirmation_link}")
    
    # In a real app:
    # msg = Message(
    #     'Confirm Your Privana Account',
    #     recipients=[user_email],
    #     body=f'Please click the following link to confirm your email: {confirmation_link}'
    # )
    # mail.send(msg)