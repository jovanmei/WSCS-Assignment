import hashlib
import re
import validators
from flask import Flask, request, jsonify
import redis

# Create Flask app and set Redis URL
app = Flask(__name__)
app.config['REDIS_URL'] = 'redis://localhost:6379/0'

# Connect to Redis database
db = redis.Redis.from_url(app.config['REDIS_URL'])

# Define Url class to store URLs and their hashes
class Url:
    def __init__(self, value):
        self.value = value
        self.hash = self.hash_value()

    # Generate hash value for the given URL
    def hash_value(self):
        hasher = hashlib.sha256()
        hasher.update(self.value.encode('utf-8'))
        return hasher.hexdigest()[:4]

# Create a shortened URL
@app.route('/', methods=['POST'])
def create():
    # Get the URL string from the request
    value = request.json['value']

    # Check if the value matches a URL format
    if validators.url(value):
        url = Url(value=value)
        db.set(url.hash, url.value)

        # Return the hash value
        return jsonify({'value': url.hash}), 201
    else:
        return jsonify({'error': 'Invalid URL format'}), 400

# Get all shortened URLs
@app.route('/', methods=['GET'])
def get_all():
    output = []
    # Iterate over all keys in the Redis database
    for key in db.scan_iter():
        # Append each URL and its hash to the output list
        output.append({'value': db.get(key).decode('utf-8'), 'hash': key.decode('utf-8')})

    # Return the list of all URLs and their hashes
    return jsonify({'urls': output}), 200

# Get the original URL for a given hash
@app.route('/<hash>', methods=['GET'])
def get(hash):
    value = db.get(hash)
    if not value:
        return jsonify({'message': 'URL not found'}), 404

    # Return the original URL and its hash
    return jsonify({'value': value.decode('utf-8'), 'hash': hash}), 200

# Update the original URL for a given hash
@app.route('/<hash>', methods=['PUT'])
def update(hash):
    value = db.get(hash)
    if not value:
        return jsonify({'message': 'URL not found'}), 404

    # Get the new URL from the request
    new_value = request.json['value']

    # Check if the new URL is valid
    if validators.url(new_value):
        new_hash = Url(value=new_value).hash
        db.delete(hash)
        db.set(new_hash, new_value)

        # Return the updated URL and its new hash
        return jsonify({'value': new_value, 'hash': new_hash})
    else:
        return jsonify({'error': 'Invalid URL format'}), 400

# Delete a shortened URL by its hash
@app.route('/<hash>', methods=['DELETE'])
def delete(hash):
    value = db.get(hash)
    if not value:
        return jsonify({'message': 'URL not found'}), 404

    # Delete the URL from the Redis database
    db.delete(hash)
    return '', 204

# Delete all shortened URLs
@app.route('/', methods=['DELETE'])
def delete_all():
    # Flush the Redis database
    db.flushdb()
    return '', 204

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)


