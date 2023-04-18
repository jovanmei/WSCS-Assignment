import hashlib
import time
import validators
import re
from flask import Flask, request, jsonify
import redis
import jwt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)

from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask_jwt_extended import create_access_token

# Create Flask application
app = Flask(__name__)

# Configure Redis connection
app.config['REDIS_URL'] = 'redis://localhost:6379/0'

# Configure JWT secret key
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Replace with your own secret key

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///auth.db"
sdb = SQLAlchemy(app)

# Initialize JWTManager
jwt = JWTManager(app)

# Connect to Redis database
db = redis.Redis.from_url(app.config['REDIS_URL'])


class User(sdb.Model):
    id = sdb.Column(sdb.Integer, primary_key=True)
    username = sdb.Column(sdb.String(80), unique=True, nullable=False)
    password = sdb.Column(sdb.String(255), nullable=False)


@app.route("/register", methods=["POST"])
def register():
    username = request.json["username"]
    password = request.json["password"]

    # Check if the user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Duplicate"}), 409

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    user = User(username=username, password=hashed_password)
    sdb.session.add(user)
    sdb.session.commit()

    return jsonify({"message": "Successfully registered"}), 201


@app.route("/login", methods=["POST"])
def login():
    username = request.json["username"]
    password = request.json["password"]
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode("utf-8"), user.password):
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200

    return jsonify({"message": "forbidden"}), 403


@app.route("/update", methods=["PUT"])
def update_password():
    username = request.json["username"]
    old_password = request.json["old_password"]
    new_password = request.json["new_password"]

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Check if old password is correct
    if not bcrypt.checkpw(old_password.encode("utf-8"), user.password):
        return jsonify({"message": "Forbidden"}), 403

    # Hash the new password and update the user object
    hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    user.password = hashed_password

    # Commit changes to the database
    sdb.session.commit()

    return jsonify({"message": "Password updated successfully"}), 200


# the regex below is from the validators.py from django
regex = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https:// or ftp(s)://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port number
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # match the path and query string of the URL


# URL class to store URL value and its hash
class Url:
    def __init__(self, value):
        self.value = value
        self.hash = self.hash_value()

    # Generate a unique hash based on the URL value and current timestamp
    def hash_value(self):
        hasher = hashlib.sha256()
        hasher.update(self.value.encode('utf-8'))
        timestamp = str(int(time.time()))[-2:]
        short_hash = hasher.hexdigest()[:2]
        return f"{timestamp}{short_hash}"


# Check if the given URL is already in the database, return its hash if found
def get_existing_hash(url_value):
    for key in db.scan_iter():
        if db.get(key).decode('utf-8') == url_value:
            return key.decode('utf-8')
    return None


# Create a new short URL
@app.route('/', methods=['POST'])
@jwt_required()
def create():
    value = request.json['value']

    # Validate the URL
    if not re.match(regex, value):
        return jsonify({'error': 'Invalid URL format'}), 400

    # Check if the URL already exists in the database
    existing_hash = get_existing_hash(value)
    if existing_hash:
        # Return the existing hash with a warning message
        return jsonify({'value': existing_hash, 'warning': 'URL already exists in the database'}), 200

    # Create a new URL object and store it in the database
    url = Url(value=value)
    db.set(url.hash, url.value)

    # Return the new hash
    return jsonify({'value': url.hash}), 201


# Get all short URLs
@app.route('/', methods=['GET'])
@jwt_required()
def get_all():
    output = []
    # Iterate through the database keys and append the URL values and hashes to the output
    for key in db.scan_iter():
        output.append({'value': db.get(key).decode('utf-8'), 'hash': key.decode('utf-8')})
    return jsonify({'urls': output}), 200


# Get the original URL for a short URL
@app.route('/<hash>', methods=['GET'])
@jwt_required()
def get(hash):
    value = db.get(hash)
    if not value:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    # Return the original URL and hash
    return jsonify({'value': value.decode('utf-8'), 'hash': hash}), 200


# Update a short URL with a new URL
@app.route('/<hash>', methods=['PUT'])
@jwt_required()
def update(hash):
    value = db.get(hash)
    if not value:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    new_value = request.json['value']
    # Validate the new URL
    if not re.match(regex, new_value):
        return jsonify({'error': 'Invalid URL format'}), 400

    # Create a new hash for the updated URL
    new_hash = Url(value=new_value).hash
    # Remove the old hash from the database and add the new one
    db.delete(hash)
    db.set(new_hash, new_value)
    return jsonify({'value': new_value, 'hash': new_hash}), 200


# Delete a short URL
@app.route('/<hash>', methods=['DELETE'])
@jwt_required()
def delete(hash):
    value = db.get(hash)
    if not value:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    # Delete the URL from the database
    db.delete(hash)
    return '', 204


# Delete all short URLs
@app.route('/', methods=['DELETE'])
@jwt_required()
def delete_all():
    # Flush the Redis database
    db.flushdb()
    return '', 204


# Run the Flask application
if __name__ == '__main__':
    # Mac OSX Monterey (12.x) currently uses ports 5000 and 7000 for its Control centre hence the issue.
    # So just run the app from port other than 5000 and 7000
    app.run(debug=True, port=8000)
