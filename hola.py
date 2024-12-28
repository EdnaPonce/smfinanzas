from flask import Flask
from login import login_bp  # Importamos el Blueprint

app = Flask(__name__)

# Registrar el Blueprint del login
app.register_blueprint(login_bp)

if __name__ == "__main__":
    app.run(debug=True)
