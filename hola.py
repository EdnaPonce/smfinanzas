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
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from sqlalchemy.sql import text
import phonenumbers
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
import phonenumbers
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from mailersend.emails import NewEmail
import json  # Agregar esta línea
import stripe

app = Flask(__name__)
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000")  # Valor por defecto si no se encuentra
CORS(app, resources={r"/*": {"origins": cors_origins}})
#CORS(app, resources={r"/*": {"origins": "v0-conexion-nz5vsdqjgqc.vercel.app/"}})

# Función para generar un id_token único
def generate_unique_id_token():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=9))
# Configuración de conexión a PostgreSQL
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  
# Inicializar SQLAlchemy
db = SQLAlchemy(app)

# Configuración del remitente y destinatario
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
EMAIL_FROM = os.getenv('EMAIL_FROM')

# Inicializar PasswordHasher
ph = PasswordHasher()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")  # O directamente la clave
# Modelo para la tabla existente (ajusta según tus columnas)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)  # Agrega el índice
    password = db.Column(db.String(200), nullable=False)
    id_token = db.Column(db.String(36), unique=True, nullable=False, index=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    promo_validated = db.Column(db.Boolean, default=False)  # Asegúrate de que esta columna esté aquí
    pay_success = db.Column(db.Boolean, default=False)  # Asegúrate de que esta columna esté aquí
    updatedAt = db.Column(db.DateTime, nullable=False, default=db.func.now(), onupdate=db.func.now())  # Campo para rastrear actualizaciones

class Sale(db.Model):
    __tablename__ = 'sales'

    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)  # Agregar índice
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)  # Agregar índicer
    course_price = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    commission_level_1 = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    commission_level_2 = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    commission_level_3 = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    commission_level_4 = db.Column(db.Numeric(10, 2), nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())

    # Define relationships for easier access
    buyer = db.relationship('User', foreign_keys=[buyer_id])
    seller = db.relationship('User', foreign_keys=[seller_id])


def send_welcome_email(to_email, user_name, user_email, user_password):
    
    subject = "El Primer Paso hacia tu Transformación Financiera 🎉"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Design</title>
        <style>
            body {{
                font-family: 'Roboto', sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f2f2f2;
            }}
            .email-container {{
                max-width: 600px;
                margin: 0 auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                background-color: #003399;
                padding: 20px;
                text-align: center;
                color: #ffffff;
            }}
            .content {{
                padding: 20px;
                color: #333333;
            }}
            .footer {{
                background-color: #003399;
                color: #ffffff;
                padding: 20px;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="header">
                <h1>El Primer Paso hacia tu Transformación Financiera 🎉</h1>
            </div>
            <div class="content">
                <h1>Hola {user_name},</h1>
                <p>¡Bienvenido a Minds! 🚀</p>
                <p>Estamos IMPACTADOS de que te atreviste a dar el primer paso hacia tu transformación financiera.</p>
                <p>Tu correo: <strong>{user_email}</strong></p>
                <p>Tu contraseña: <strong>{user_password}</strong></p>
            <div class="section">
                <h2>¿Qué sigue?</h2>
                <ul>
                  <li>Explora el módulo gratuito del Programa de Transformación Financiera (PTF). Este contenido inicial te ayudará a concientizarte sobre tu relación con el dinero para llevarte al camino de la Transformación Financiera.</li>
                </ul>
            </div>

            <div class="section">
                <p><strong>Estamos aquí para ti</strong></p>
                <p>Tu progreso es nuestra prioridad. En Minds, queremos empoderarte con los conocimientos, herramientas y estrategias necesarias para que logres una vida libre de preocupaciones financieras y llena de oportunidades.</p>
                <p>Mantente atento a más novedades y recuerda: el futuro está en tus manos. 🏆</p>
            </div>
        </div>
            <div class="footer">
                <p>Equipo Minds</p>
            </div>
        </div>
    </body>
    </html>
    """
    mailer = NewEmail(SENDGRID_API_KEY)
    recipients = [{'email': to_email, 'name': user_name}]
    # Preparar los datos del correo
    email_data = {
        "from": {"email": EMAIL_FROM, "name": "Minds Team"},
        "to": recipients,
        "subject": subject,
        "html": html_content,
        "text": f"Hola {user_name}, Bienvenido a Minds. Tu correo es {user_email} y tu contraseña es {user_password}."
    }

    try:
        response = mailer.send(email_data)
        print(f"Correo enviado exitosamente a {to_email}, ID: {response}")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")


@app.route('/register', methods=['POST'])
def register():
    start_time = time.time()  # Inicio del proceso general
    times = {}  # Diccionario para almacenar tiempos por secciones
    # Inicio procesamiento de datos
    t0 = time.time()
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON payload'}), 400
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    phone = ''.join(filter(str.isdigit, data.get('phone', '').strip()))
    password = data.get('password', '').strip()
    seller_token = (data.get('seller_token') or '').strip()  # Código opcional del vendedor
    times['data_processing'] = time.time() - t0

    # Validación de campos
    t0 = time.time()
    if not all([name, email, phone, password]):
        return jsonify({'error': 'All fields are required'}), 400
    if len(password) < 5:
        return jsonify({'error': 'Password must be at least 5 characters long'}), 400
    times['validation'] = time.time() - t0

    # Hash de la contraseña
    t0 = time.time()
    hashed_password = ph.hash(password)
    id_token = str(uuid.uuid4()).replace('-', '')[:12]
    times['hashing_password'] = time.time() - t0

    # Verificación de unicidad del id_token
    t0 = time.time()
    times['id_token_uniqueness_check'] = time.time() - t0

    # Buscar vendedor (si existe)
    t0 = time.time()
    seller = None
    course_price = 0.0
    if seller_token:
        seller = db.session.execute(
            db.select(User).filter(User.id_token == seller_token)
        ).scalar_one_or_none()
        if not seller:
            return jsonify({'error': 'Código de referencia no encontrado'}), 400
    times['seller_lookup'] = time.time() - t0

    # Verificación de usuario existente
    t0 = time.time()
    existing_user = User.query.filter((User.email == email) | (User.phone == phone)).first()
    if existing_user:
        return jsonify({'error': 'Email or phone already exists'}), 400
    times['user_existence_check'] = time.time() - t0

    try:
        db.session.rollback()  # Limpiar sesión antes de agregar
        # Ajuste de secuencia manualmente
        t0 = time.time()
       # max_id = db.session.query(db.func.max(User.id)).scalar() or 0
       # db.session.execute(text("SELECT setval('users_id_seq', :max_id)"), {'max_id': max_id})
       # db.session.commit()
        times['sequence_adjustment'] = time.time() - t0

        # Crear nuevo usuario
        t0 = time.time()
        new_user = User(
            name=name,
            email=email,
            phone=phone,
            password=hashed_password,
            id_token=id_token,
            promo_validated=False,
            pay_success=False
        )
        db.session.add(new_user)
        db.session.commit()
        times['user_creation'] = time.time() - t0
      
        # Procesamiento de comisiones del vendedor
# Procesamiento de comisiones del vendedor
        t0 = time.time()
        if seller:
            commission_levels = {
                'commission_level_1': 500.0,  # Nivel 1: 500
                'commission_level_2': 200.0,  # Nivel 2: 200
                'commission_level_3': 100.0,  # Nivel 3: 100
                'commission_level_4': 50.0    # Nivel 4: 50
            }
            print(Sale.__table__.columns.keys())

            # Crear un lote de ventas para inserción masiva
            sales = [
                Sale(
                    buyer_id=new_user.id,
                    seller_id=seller.id,
                    course_price=2199.0 if new_user.pay_success else 0.0,  # Precio del curso
                    **commission_levels  # Asignar comisiones fijas
                )
            ]
            # Insertar todas las ventas en una sola transacción
            db.session.bulk_save_objects(sales)
            db.session.commit()

        # Generar token JWT
        token_payload = {
            'id': new_user.id,
            'name': new_user.name,
            'email': new_user.email,
            'id_token': id_token,
            'exp': datetime.now(timezone.utc) + timedelta(hours=20)
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        times['jwt_token_generation'] = time.time() - t0

        # Enviar correo de bienvenida
        t0 = time.time()
# Enviar correo de bienvenida
        t0 = time.time()
        try:
            send_welcome_email(email, name, email, password)
        except Exception as e:
            print(f"Usuario registrado, pero error al enviar correo: {str(e)}")

        times['email_sending'] = time.time() - t0

        # Finalización y respuesta
        total_time = time.time() - start_time
        print(f"Tiempo total: {total_time:.4f} segundos")
        print("Desglose de tiempos por sección:", times)

        return jsonify({
            'message': 'User registered successfully!',
            'token': token,
            'id_token': id_token,
            'id': new_user.id,
            'seller': seller.name if seller else 'No seller',
            'course_price': course_price,
            'execution_times': times  # Devolver tiempos de ejecución para depuración
        }), 201

    except IntegrityError as e:
        db.session.rollback()
        print(f"IntegrityError details: {e.orig}")
        return jsonify({'error': 'Email or phone already exists', 'details': str(e.orig)}), 400

    except Exception as e:
        db.session.rollback()
        print(f"Error inesperado: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500



# Ruta para login@app.route('/login', methods=['POST'])
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if user:
        try:
            # Verificar la contraseña
            ph.verify(user.password, password)
            
            # Actualizar el campo `updatedAt` con la hora actual en UTC
            user.updatedAt = datetime.now(timezone.utc)
            db.session.commit()

            # Generar token JWT
            token = jwt.encode({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'id_token': user.id_token,
                'exp': datetime.now(timezone.utc) + timedelta(hours=1)  # Usar datetime con timezone
            }, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({
                'message': 'Login successful!',
                'token': token,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'promo_validated': user.promo_validated,
                    'id_token': user.id_token or 'Sin código'
                }
            }), 200

        except VerifyMismatchError:
            return jsonify({'error': 'Invalid email or password'}), 401
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/api/validate-promo', methods=['POST'])
def validate_promo():
    data = request.json
    user_id = data.get('user_id')  # ID del usuario en la base de datos
    promo_code = data.get('promo_code')  # Código promocional

    if promo_code == '20250113xo2wQKlñ':
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        user.promo_validated = True
        db.session.commit()
        return jsonify({'message': 'Código validado exitosamente'})
    else:
        return jsonify({'error': 'Código promocional incorrecto'}), 400

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    
    try:
        event = json.loads(payload)  # Convertir el JSON recibido a un diccionario
        print(f"📡 Webhook recibido: {json.dumps(event, indent=2)}")  # Agregar log para ver el contenido

        if event['type'] == 'checkout.session.completed':
            session = event.get('data', {}).get('object', {})  # Evita acceder a índices que no existen
            user_id = session.get('metadata', {}).get('user_id')

            if user_id:
                user = User.query.filter_by(id=user_id).first()
                if user:
                    user.pay_success = True
                    db.session.commit()
                    print(f"✅ Usuario {user_id} actualizado con pago exitoso")

        return '', 200

    except Exception as e:
        print(f"❌ Error en webhook: {str(e)}")
        return '', 400


@app.route('/api/promo-status/<int:user_id>', methods=['GET'])
def promo_status(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    return jsonify({'promo_validated': user.promo_validated})
@app.route('/recover-password', methods=['POST'])
def recover_password():
    data = request.json
    email = data.get('email', '').strip()
    new_password = data.get('new_password', '').strip()

    if not email or not new_password:
        return jsonify({'error': 'Email and new password are required'}), 400

    # Buscar usuario por email
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'Email not found'}), 404

    # Validar nueva contraseña
    if len(new_password) < 5:
        return jsonify({'error': 'Password must be at least 5 characters long'}), 400

    try:
        # Hashear nueva contraseña
        hashed_password = ph.hash(new_password)
        user.password = hashed_password
        db.session.commit()

        return jsonify({'message': 'Password updated successfully!'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'An unexpected error occurred: ' + str(e)}), 500

@app.route('/register-sale', methods=['POST'])
def register_sale():
    data = request.json
    print(f"Received payload: {data}")

    buyer_token = data.get('buyer_token')
    seller_token = data.get('seller_token')

    if not buyer_token or not seller_token:
        return jsonify({'error': 'Buyer and seller IDs are required'}), 400

    # No puede registrar su propio ID
    if buyer_token == seller_token:
        return jsonify({'error': 'No puedes registrar tu propio ID'}), 400

    # Buscar comprador y vendedor por sus tokens
    buyer = User.query.filter_by(id_token=buyer_token).first()
    seller = User.query.filter_by(id_token=seller_token).first()

    if not buyer or not seller:
        return jsonify({'error': 'Buyer or seller not found'}), 404

    # Verificar si ya existe una venta para el comprador
    existing_sale = Sale.query.filter_by(buyer_id=buyer.id).first()
    if existing_sale:
        return jsonify({'error': 'El comprador ya tiene una venta registrada'}), 400

    # Calcular comisiones y registrar la venta
    try:
        course_price = 2199.0
        commission_level_1 = course_price * 0.1
        commission_level_2 = course_price * 0.05
        commission_level_3 = course_price * 0.03
        commission_level_4 = course_price * 0.02

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

        return jsonify({
            'message': 'Venta registrada exitosamente',
            'sale': {
                'name': buyer.name,
                'level': 'Directo',
                'earnings': commission_level_1,
                'date': sale.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error saving sale: {e}")
        return jsonify({'error': 'Error al registrar la venta'}), 500


        
@app.route('/get-referrals', methods=['GET'])
def get_referrals():
    token = request.args.get('token')
    if not token:
        return jsonify({'error': 'Token is required'}), 400

    try:
        # Decodificar el token
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_token.get('id')

        if not user_id:
            return jsonify({'error': 'Invalid token'}), 400

        # Configuración de porcentajes de comisiones (convertidos a Decimal)
        commission_rates = {
            1: Decimal('0.2273'),  # Nivel 1 - 10%
            2: Decimal('0.0454'),  # Nivel 2 - 5%
            3: Decimal('0.1819'),  # Nivel 3 - 3%
            4: Decimal('0.0454'),  # Nivel 4 - 3%
        }

        # Función recursiva para calcular los referrals
        def get_sales_by_level(user_id, level=1):
            if level > 4:  # Máximo nivel permitido
                return []

            sales = Sale.query.filter_by(seller_id=user_id).all()
            referrals = []

            for sale in sales:
                buyer = User.query.get(sale.buyer_id)
                if not buyer:
                    continue

                # Convertir course_price a Decimal si es necesario
                course_price = sale.course_price
                if isinstance(course_price, float):
                    course_price = Decimal(str(course_price))

                commission = course_price * commission_rates.get(level, Decimal('0'))

                referrals.append({
                    'name': buyer.name,
                    'level': f'Nivel {level}',
                    'earnings': round(commission, 2),
                    'date': sale.created_at.strftime('%Y-%m-%d'),
                })

                # Llamada recursiva para el siguiente nivel
                referrals += get_sales_by_level(buyer.id, level + 1)

            return referrals

        # Obtener referrals a partir del usuario logueado
        referrals = get_sales_by_level(user_id)
        return jsonify({'referrals': referrals}), 200

    except Exception as e:
        print('Error fetching referrals:', e)
        return jsonify({'error': 'Internal server error'}), 500


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
