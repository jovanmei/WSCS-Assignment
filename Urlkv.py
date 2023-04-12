import hashlib
import re
import validators
from flask import Flask, request, jsonify
import redis

app = Flask(__name__)
app.config['REDIS_URL'] = 'redis://localhost:6379/0'
db = redis.Redis.from_url(app.config['REDIS_URL'])


class Url:
    def __init__(self, value):
        self.value = value
        self.hash = self.hash_value()

    def hash_value(self):
        hasher = hashlib.sha256()
        hasher.update(self.value.encode('utf-8'))
        return hasher.hexdigest()[:4]


@app.route('/', methods=['POST'])
def create():
    # get the url string from the request
    value = request.json['value']

    # check if the value matches a URL format
    if validators.url(value):
        url = Url(value=value)
        db.set(url.hash, url.value)
        
        # return the hash value
        return jsonify({'value': url.hash}), 201
    else:
        return jsonify({'error': 'Invalid URL format'}), 400


@app.route('/', methods=['GET'])
def get_all():
    output = []
    for key in db.scan_iter():
        output.append({'value': db.get(key).decode('utf-8'), 'hash': key.decode('utf-8')})
    return jsonify({'urls': output}), 200


@app.route('/<hash>', methods=['GET'])
def get(hash):
    value = db.get(hash)
    if not value:
        return jsonify({'message': 'URL not found'}), 404
    return jsonify({'value': value.decode('utf-8'), 'hash': hash}), 301


@app.route('/<hash>', methods=['PUT'])
def update(hash):
    value = db.get(hash)
    if not value:
        return jsonify({'message': 'URL not found'}), 404
    new_value = request.json['value']
    if validators.url(new_value):
        new_hash = Url(value=new_value).hash
        db.delete(hash)
        db.set(new_hash, new_value)
        return jsonify({'value': new_value, 'hash': new_hash})
    else:
        return jsonify({'error': 'Invalid URL format'}), 400


@app.route('/<hash>', methods=['DELETE'])
def delete(hash):
    value = db.get(hash)
    if not value:
        return jsonify({'message': 'URL not found'}), 404
    db.delete(hash)
    return '', 204


@app.route('/', methods=['DELETE'])
def delete_all():
    db.flushdb()
    return '', 204


if __name__ == '__main__':
    app.run(debug=True)

