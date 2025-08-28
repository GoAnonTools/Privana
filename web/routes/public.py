# web/routes/public.py
from flask import Blueprint, render_template
from flask_login import login_required, current_user

public_bp = Blueprint("public", __name__)

@public_bp.get("/welcome")
@login_required
def welcome():
    # Make sure Jinja gets a user object
    return render_template("welcome.html", user=current_user)