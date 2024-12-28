from flask import Blueprint, render_template

register_bp = Blueprint('register', __name__, template_folder='templates')

@register_bp.route('/register')
def register():
    return render_template('register.html')
