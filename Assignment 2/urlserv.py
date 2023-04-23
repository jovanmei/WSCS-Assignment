import hashlib
import threading
import time
import re
import base64
import hmac
import json
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import secrets

# Create Flask application
app = Flask(__name__)

# Configure JWT secret key
SECRET_KEY = 'super-secret'  # Replace with your own secret key

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///auth.db"
sdb = SQLAlchemy(app)


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

    def hash_value(self):
        hasher = hashlib.sha256()
        hasher.update(self.value.encode('utf-8'))
        timestamp = str(int(time.time()))[-2:]
        short_hash = hasher.hexdigest()[:2]
        return f"{timestamp}{short_hash}"

# Create a dictionary to store the tokens and their associated user IDs
TOKENS = {}

# Function to generate a new token for a given user ID
def jwt_encode(user_id):
    token = hashlib.sha256(str(user_id).encode('utf-8')).hexdigest()
    TOKENS[token] = user_id
    return token


# Function to get the user ID associated with a given token
def get_user_id(token):
    return TOKENS.get(token)


# Decorator function to verify token in the request
def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get the token from the request headers
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"message": "Missing token"}), 401

        # Check if the token is valid
        user_id = get_user_id(token)
        if not user_id:
            return jsonify({"message": "Invalid token"}), 401

        # Store the user ID in the Flask global object for use in the decorated function
        g.jwt_identity = user_id
        return f(*args, **kwargs)

    return decorated_function

# Function to clear the TOKENS dictionary every hour
def clear_tokens():
    while True:
        time.sleep(3600)
        TOKENS.clear()

# Start a new thread to clear the TOKENS dictionary every hour
threading.Thread(target=clear_tokens, daemon=True).start()

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    new_user = User(username=username, password=hashed_password)
    sdb.session.add(new_user)
    sdb.session.commit()

    return jsonify({"message": "User created"}), 201


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = jwt_encode(user.id)
    return jsonify(access_token=access_token), 200


# Change the password
@app.route("/users", methods=["PUT"])
@jwt_required
def update_password():
    # jwt authentication(only the person who login can change his password)
    user_id = g.jwt_identity
    username = request.json["username"]
    old_password = request.json["old-password"]
    new_password = request.json["new-password"]

    user = User.query.filter_by(username=username).first()
    # Check if the current user is authorized
    if user.id != user_id:
        return jsonify({"message": "Unauthorized user"}), 401
    # Check if the user exists
    if not user:
        return jsonify({"message": "User not found"}), 404

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
@jwt_required
def create():
    current_user_id = g.jwt_identity
    value = request.json['value']

    # Validate the URL
    if not re.match(regex, value):
        return jsonify({'error': 'Invalid URL format'}), 400

    # Check if the URL already exists in the database
    existing_url = Url.query.filter_by(value=value, user_id=current_user_id).first()
    if existing_url:
        # Return the existing hash with a warning message
        return jsonify({'value': existing_url.hash, 'warning': 'URL already exists in the database'}), 200

    # Create a new URL object and store it in the database
    url = Url(value=value, user_id=current_user_id)
    sdb.session.add(url)
    sdb.session.commit()

    # Return the new hash
    return jsonify({'value': url.hash}), 201


# Get all short URLs for the current user
@app.route('/', methods=['GET'])
@jwt_required
def get_all():
    current_user_id = g.jwt_identity
    output = []
    # Iterate through the user's URLs and append the URL values and hashes to the output
    for url in User.query.get(current_user_id).urls:
        output.append({'value': url.value, 'hash': url.hash})
    return jsonify({'urls': output}), 200


# Get the original URL for a short URL
@app.route('/<hash>', methods=['GET'])
@jwt_required
def get(hash):
    current_user_id = g.jwt_identity
    url = Url.query.filter_by(hash=hash, user_id=current_user_id).first()
    if not url:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    # Return the original URL and hash
    return jsonify({'value': url.value, 'hash': hash}), 200


# Update a short URL with a new URL
@app.route('/<hash>', methods=['PUT'])
@jwt_required
def update(hash):
    current_user_id = g.jwt_identity
    url = Url.query.filter_by(hash=hash, user_id=current_user_id).first()
    if not url:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    new_value = request.json['value']
    # Validate the new URL
    if not re.match(regex, new_value):
        return jsonify({'error': 'Invalid URL format'}), 400

    # Check if the new URL already exists in the database
    existing_url = Url.query.filter_by(value=new_value, user_id=current_user_id).first()
    if existing_url:
        # Return the existing hash with a warning message
        return jsonify({'value': existing_url.hash, 'warning': 'URL already exists in the database'}), 200

    # Create a new hash for the updated URL
    new_hash = Url(value=new_value, user_id=current_user_id).hash
    # Update the URL object with the new value and hash
    url.value = new_value
    url.hash = new_hash
    # Commit changes to the database
    sdb.session.commit()
    return jsonify({'value': new_value, 'hash': new_hash}), 200


# Delete a short URL
@app.route('/<hash>', methods=['DELETE'])
@jwt_required
def delete(hash):
    current_user_id = g.jwt_identity
    url = Url.query.filter_by(hash=hash, user_id=current_user_id).first()
    if not url:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    # Delete the URL from the database
    sdb.session.delete(url)
    sdb.session.commit()
    return '', 204


# Delete all short URLs for the current user
@app.route('/', methods=['DELETE'])
@jwt_required
def delete_all():
    current_user_id = g.jwt_identity
    # Delete all URLs for the current user
    Url.query.filter_by(user_id=current_user_id).delete()
    sdb.session.commit()
    return '', 204


# Run the Flask application
if __name__ == '__main__':
    # Mac OSX Monterey (12.x) currently uses ports 5000 and 7000 for its Control centre hence the issue.
    # So just run the app from port other than 5000 and 7000
    with app.app_context():
        sdb.create_all()
    app.run(debug=True, port=8000)