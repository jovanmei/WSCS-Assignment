import hashlib
import time
import validators
import re
from flask import Flask, request, jsonify
import redis

# Create Flask application
app = Flask(__name__)
# Configure Redis connection
app.config['REDIS_URL'] = 'redis://localhost:6379/0'
# Connect to Redis database
db = redis.Redis.from_url(app.config['REDIS_URL'])

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
def create():
    value = request.json['value']

    # Validate the URL
    # if validators.url(value):
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

    # else:
    #     # Invalid URL format
    #     return jsonify({'error': 'Invalid URL format'}), 400


# Get all short URLs
@app.route('/', methods=['GET'])
def get_all():
    output = []
    # Iterate through the database keys and append the URL values and hashes to the output
    for key in db.scan_iter():
        output.append({'value': db.get(key).decode('utf-8'), 'hash': key.decode('utf-8')})
    return jsonify({'urls': output}), 200


# Get the original URL for a short URL
@app.route('/<hash>', methods=['GET'])
def get(hash):
    value = db.get(hash)
    if not value:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    # Return the original URL and hash
    return jsonify({'value': value.decode('utf-8'), 'hash': hash}), 200


# Update a short URL with a new URL
@app.route('/<hash>', methods=['PUT'])
def update(hash):
    value = db.get(hash)
    if not value:
        # URL not found
        return jsonify({'message': 'URL not found'}), 404
    new_value = request.json['value']
    # Validate the new URL
    # if validators.url(new_value):
    if not re.match(regex, new_value):
        return jsonify({'error': 'Invalid URL format'}), 400

    # Create a new hash for the updated URL
    new_hash = Url(value=new_value).hash
    # Remove the old hash from the database and add the new one
    db.delete(hash)
    db.set(new_hash, new_value)
    return jsonify({'value': new_value, 'hash': new_hash}), 200
    # else:
    #     # Invalid URL format
    #     return jsonify({'error': 'Invalid URL format'}), 400


# Delete a short URL
@app.route('/<hash>', methods=['DELETE'])
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
def delete_all():
    # Flush the Redis database
    db.flushdb()
    return '', 204


# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
