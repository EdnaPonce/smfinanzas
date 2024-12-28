from flask import Flask
from login import login_bp
from register import register_bp

app = Flask(__name__)

# Registrar los Blueprints
app.register_blueprint(login_bp)
app.register_blueprint(register_bp)

if __name__ == "__main__":
    app.run(debug=True)
