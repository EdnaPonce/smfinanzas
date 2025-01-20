from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
from dotenv import load_dotenv
import time
import jwt
from datetime import datetime, timedelta
from functools import wraps
import random
import string

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://kzmg1z3fkm4rmhwcyq2g.lite.vusercontent.net"}})

# Función para generar un id_token único
def generate_unique_id_token():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=9))
# Configuración de conexión a PostgreSQL
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  
# Inicializar SQLAlchemy
db = SQLAlchemy(app)

# Inicializar PasswordHasher
ph = PasswordHasher()

# Modelo para la tabla existente (ajusta según tus columnas)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)  # Agrega el índice
    password = db.Column(db.String(200), nullable=False)
    id_token = db.Column(db.String(10), unique=True, nullable=False)  # Add this line
    sponsor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    sponsor = db.relationship('User', remote_side=[id], backref='referrals')

class Sale(db.Model):
    __tablename__ = 'sales'

    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Assumes 'users' table exists
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ForeignKey for the seller
    course_price = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    commission_level_1 = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    commission_level_2 = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    commission_level_3 = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    commission_level_4 = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())

    # Define relationships for easier access
    buyer = db.relationship('User', foreign_keys=[buyer_id])
    seller = db.relationship('User', foreign_keys=[seller_id])


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')

    # Validación básica
    if not all([name, email, phone, password]):
        return jsonify({'error': 'All fields are required'}), 400

    # Generar hash de contraseña y ID único
    hashed_password = ph.hash(password)
    id_token = generate_unique_id_token()

    try:
        # Intentar agregar el nuevo usuario
        new_user = User(name=name, email=email, phone=phone, password=hashed_password, id_token=id_token)
        db.session.add(new_user)
        db.session.commit()

        # Generar token JWT
        token = jwt.encode({
            'id': new_user.id,
            'name': new_user.name,
            'email': new_user.email,
            'id_token': id_token,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'message': 'User registered successfully!', 'token': token, 'id_token': id_token}), 201

    except Exception as e:
        # Manejar errores y registrar detalles para depuración
        db.session.rollback()
        print("Error al registrar el usuario:", str(e))  # Añade esto para ver el error exacto
        return jsonify({'error': 'User already exists or invalid data'}), 400

# Ruta para login@app.route('/login', methods=['POST'])
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400

    # Consulta optimizada para obtener todos los datos del usuario
    user = User.query.filter_by(email=email).first()

    if user:
        try:
            # Verificar la contraseña
            ph.verify(user.password, password)
            
            # Generar token JWT
            token = jwt.encode({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'id_token': user.id_token,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({
                'message': 'Login successful!',
                'token': token,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'id_token': user.id_token or 'Sin código'
                }
            }), 200

        except VerifyMismatchError:
            return jsonify({'error': 'Invalid email or password'}), 401
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/register-sale', methods=['POST'])
def register_sale():
    data = request.json
    print("Received payload:", data)

    buyer_token = data.get('buyer_token')
    seller_token = data.get('seller_token')

    if not buyer_token or not seller_token:
        return jsonify({'error': 'Buyer and seller IDs are required'}), 400

    # Find buyer and seller
    buyer = User.query.filter_by(id_token=buyer_token).first()
    seller = User.query.filter_by(id_token=seller_token).first()

    if not buyer or not seller:
        return jsonify({'error': 'Invalid buyer or seller token'}), 400

    # Calculate commissions
    course_price = 2199.00
    commission_level_1 = course_price * 0.25
    commission_level_2 = course_price * 0.10
    commission_level_3 = course_price * 0.05
    commission_level_4 = course_price * 0.02

    try:
        # Create and save the sale record
        sale = Sale(
            buyer_id=buyer.id,
            seller_id=seller.id,
            course_price=course_price,
            commission_level_1=commission_level_1,
            commission_level_2=commission_level_2,
            commission_level_3=commission_level_3,
            commission_level_4=commission_level_4,
        )
        db.session.add(sale)
        db.session.commit()

        return jsonify({'message': 'Sale registered successfully!', 'sale': {
            'id': sale.id,
            'buyer_id': sale.buyer_id,
            'seller_id': sale.seller_id,
            'course_price': str(sale.course_price),
            'commission_level_1': str(sale.commission_level_1),
            'commission_level_2': str(sale.commission_level_2),
            'commission_level_3': str(sale.commission_level_3),
            'commission_level_4': str(sale.commission_level_4),
            'created_at': sale.created_at,
        }}), 201

    except Exception as e:
        db.session.rollback()
        print("Error saving sale:", e)
        return jsonify({'error': 'Failed to register sale'}), 500
        
@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        # Verificación de la firma del webhook
        event = stripe.Webhook.construct_event(payload, sig_header, WEBHOOK_SECRET)
    except ValueError:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400

    # Verificar el tipo de evento recibido
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session['metadata']['user_id']  # Obtener el user_id de los metadatos

    return jsonify({'status': 'success'}), 200

@app.route('/get-sales', methods=['GET'])
def get_sales():
    token = request.headers.get('Authorization')  # Expecting the token in the Authorization header

    if not token:
        return jsonify({'error': 'Authorization token is required'}), 401

    # Decode the token and get the user's id_token
    payload = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=["HS256"])
    seller_id_token = payload.get('id_token')

    seller = User.query.filter_by(id_token=seller_id_token).first()
    if not seller:
        return jsonify({'error': 'Invalid token'}), 401

    # Fetch sales where the logged-in user is the seller
    sales = Sale.query.filter_by(seller_id=seller.id).all()

    # Prepare sales data to send to the frontend
    sales_data = []
    for sale in sales:
        buyer = User.query.get(sale.buyer_id)
        sales_data.append({
            'name': buyer.name if buyer else 'Unknown',
            'level': 'Direct',  # Adjust based on your business logic
            'earnings': float(sale.commission_level_1),  # Commission for this level
            'date': sale.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        })

    return jsonify(sales_data), 200


@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'error': 'Token is missing!'}), 401

    try:
        # Decodifica el token
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': 'Access granted', 'data': decoded}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token!'}), 401

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401

        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = decoded  # Agregar los datos del usuario al request
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token!'}), 401

        return f(*args, **kwargs)
    return decorated

# Usar el decorador
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard():
    return jsonify({'message': f"Welcome, {request.user['name']}!"})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000) 
