import json
import time
import re
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import base64
import datetime
import hashlib
import hmac

SECRET_KEY = "mysecretkey"
JWT_EXP_DELTA_SECONDS = 60 * 60  # 1 hour


def create_jwt_token(payload):
    # Encode header
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    header = base64.b64encode(str(header).encode()).decode().rstrip("=")

    # Encode payload
    payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    payload = base64.b64encode(str(payload).encode()).decode().rstrip("=")

    # Create signature
    signature = hmac.new(SECRET_KEY.encode(), (header + "." + payload).encode(), hashlib.sha256).digest()
    signature = base64.b64encode(signature).decode().rstrip("=")

    # Return JWT
    return header + "." + payload + "." + signature


def verify_jwt_token(token):
    # Split token into header, payload and signature
    parts = token.split(".")
    header = parts[0]
    payload = parts[1]
    signature = parts[2]

    # Check signature
    expected_signature = hmac.new(SECRET_KEY.encode(), (header + "." + payload).encode(), hashlib.sha256).digest()
    expected_signature = base64.b64encode(expected_signature).decode().rstrip("=")
    if expected_signature != signature:
        raise Exception("Invalid signature")

    # Decode payload
    payload = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode()
    payload = payload.replace("datetime.datetime", "").replace("(", "[").replace(")", "]").replace("'", "\"")
    payload = json.loads(payload)
    # Check expiration time
    exp = datetime.datetime(*payload["exp"])
    now = datetime.datetime.utcnow()
    # if exp < now:
    #     raise Exception("Token expired")

    return payload


# Create Flask application
app = Flask(__name__)

# Configure JWT secret key
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Replace with your own secret key

# Set the URI for the ElephantSQL instance
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://wirvdajm:1hV8nCETijboyuAfkD299HkaWHwA20j_@balarama.db.elephantsql.com/wirvdajm"

# Set the SQLAlchemy track modifications flag to False
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////app/instance/auth.db"

sdb = SQLAlchemy(app)

# # Initialize JWTManager
# jwt = JWTManager(app)


class User(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    username = sdb.Column(sdb.String(80), unique=True, nullable=False)
    password = sdb.Column(sdb.String(255), nullable=False)
    urls = sdb.relationship('Url', backref='user', lazy=True)


class Url(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    value = sdb.Column(sdb.String(1000), nullable=False)
    hash = sdb.Column(sdb.String(10), nullable=False)
    user_id = sdb.Column(sdb.Integer, sdb.ForeignKey('user.id'), nullable=False)

    def __init__(self, value, user_id):
        self.value = value
        self.hash = self.hash_value()
        self.user_id = user_id

    # Generate a unique hash based on the URL value and current timestamp

    def hash_value(self):
        hasher = hashlib.sha256()
        hasher.update(self.value.encode('utf-8'))
        timestamp = str(int(time.time()))[-2:]
        short_hash = hasher.hexdigest()[:2]
        return f"{timestamp}{short_hash}"


@app.route("/users", methods=["POST"])
def register():
    username = request.json["username"]
    password = request.json["password"]

    # Check if the user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Duplicate"}), 409

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    print(hashed_password)
    user = User(username=username, password=hashed_password.decode("utf-8"))
    sdb.session.add(user)
    sdb.session.commit()

    return jsonify({"message": "Successfully registered"}), 201


@app.route("/users/login", methods=["POST"])
def login():
    username = request.json["username"]
    password = request.json["password"].encode("utf-8")

    user = User.query.filter_by(username=username).first()

    if type(user.password) != bytes:
        user.password = user.password.encode("utf-8")

    if user and bcrypt.checkpw(password, user.password):
        payload = {"id": user.id, "username": user.username}
        access_token = create_jwt_token(payload)
        return jsonify({"access_token": access_token}), 200

    return jsonify({"message": "(forbidden)Wrong password"}), 403


# Change the password
@app.route("/users", methods=["PUT"])
def update_password():
    # jwt authentication (only the person who login can change his password)
    # Get token from header
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"message": "Token not provided"}), 403

    # Verify token
    try:
        payload = verify_jwt_token(token)
    except Exception as e:
        return jsonify({"message": "Invalid token"}), 403
    user_id = payload["id"]
    username = request.json["username"]
    old_password = request.json["old-password"]
    new_password = request.json["new-password"]

    user = User.query.filter_by(username=username).first()

    # Check if the user exists
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Check if the current user is authorized
    if user.id != user_id:
        return jsonify({"message": "Unauthorized user"}), 401

    # Check if the old password is correct
    if not bcrypt.checkpw(old_password.encode("utf-8"), user.password):
        return jsonify({"message": "(forbidden)Incorrect password"}), 403

    # Check if the new password is the same as the old password
    if old_password == new_password:
        return jsonify({"message": "New password cannot be the same as old one"}), 400

    # Hash and update the new password
    hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    user.password = hashed_password

    sdb.session.commit()

    return jsonify({"message": "Password updated successfully"}), 200


# the regex below is from the validators.py from django
regex = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https:// or ftp(s)://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  #
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port number
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # match the path and query string of the URL


# Create a new short URL
@app.route('/', methods=['POST'])
def create():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token not provided"}), 403

    # Verify token
    try:
        payload = verify_jwt_token(token)
    except Exception as e:
        return jsonify({"message": "Invalid token"}), 403
    user_id = payload["id"]
    value = request.json['value']

    # Validate the URL
    if not re.match(regex, value):
        return jsonify({'error': 'Invalid URL format'}), 400

    # Check if the URL already exists in the database
    existing_url = Url.query.filter_by(value=value, user_id=user_id).first()
    if existing_url:
        # Return the existing hash with a warning message
        return jsonify({'value': existing_url.hash, 'warning': 'URL already exists in the database'}), 200

    # Create a new URL object and store it in the database
    url = Url(value=value, user_id=user_id)
    sdb.session.add(url)
    sdb.session.commit()

    # Return the new hash
    return jsonify({'value': url.hash}), 201


# Get all short URLs for the current user
@app.route('/', methods=['GET'])
def get_all():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token not provided"}), 403

    # Verify token
    try:
        payload = verify_jwt_token(token)
    except Exception as e:
        return jsonify({"message": "Invalid token"}), 403
    user_id = payload["id"]
    output = []
    # Iterate through the user's URLs and append the URL values and hashes to the output
    for url in User.query.get(user_id).urls:
        output.append({'value': url.value, 'hash': url.hash})
    return jsonify({'urls': output}), 301


# Get the original URL for a short URL
@app.route('/<hash>', methods=['GET'])
def get(hash):
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token not provided"}), 403

    # Verify token
    try:
        payload = verify_jwt_token(token)
    except Exception as e:
        return jsonify({"message": "Invalid token"}), 403
    user_id = payload["id"]
    url = Url.query.filter_by(hash=hash, user_id=user_id).first()
    if not url:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    # Return the original URL and hash
    return jsonify({'value': url.value, 'hash': hash}), 301


# Update a short URL with a new URL
@app.route('/<hash>', methods=['PUT'])
def update(hash):
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token not provided"}), 403

    # Verify token
    try:
        payload = verify_jwt_token(token)
    except Exception as e:
        return jsonify({"message": "Invalid token"}), 403
    user_id = payload["id"]
    url = Url.query.filter_by(hash=hash, user_id=user_id).first()
    if not url:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    new_value = request.json['value']
    # Validate the new URL
    if not re.match(regex, new_value):
        return jsonify({'error': 'Invalid URL format'}), 400

    # Check if the new URL already exists in the database
    existing_url = Url.query.filter_by(value=new_value, user_id=user_id).first()
    if existing_url:
        # Return the existing hash with a warning message
        return jsonify({'value': existing_url.hash, 'warning': 'URL already exists in the database'}), 200

    # Create a new hash for the updated URL
    new_hash = Url(value=new_value, user_id=user_id).hash
    # Update the URL object with the new value and hash
    url.value = new_value
    url.hash = new_hash
    # Commit changes to the database
    sdb.session.commit()
    return jsonify({'value': new_value, 'hash': new_hash}), 200


# Delete a short URL
@app.route('/<hash>', methods=['DELETE'])
def delete(hash):
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token not provided"}), 403

    # Verify token
    try:
        payload = verify_jwt_token(token)
    except Exception as e:
        return jsonify({"message": "Invalid token"}), 403
    user_id = payload["id"]
    url = Url.query.filter_by(hash=hash, user_id=user_id).first()
    if not url:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    # Delete the URL from the database
    sdb.session.delete(url)
    sdb.session.commit()
    return '', 204


# Delete all short URLs for the current user
@app.route('/', methods=['DELETE'])
def delete_all():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token not provided"}), 403

    # Verify token
    try:
        payload = verify_jwt_token(token)
    except Exception as e:
        return jsonify({"message": "Invalid token"}), 403
    user_id = payload["id"]
    # Delete all URLs for the current user
    Url.query.filter_by(user_id=user_id).delete()
    sdb.session.commit()
    return '', 204


# Run the Flask application
if __name__ == '__main__':
    # Mac OSX Monterey (12.x) currently uses ports 5000 and 7000 for its Control centre hence the issue.
    # So just run the app from port other than 5000 and 7000
    with app.app_context():
        sdb.create_all()
    app.run(host='0.0.0.0', port=5001, debug=True)
