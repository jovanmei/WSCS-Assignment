import hashlib
import re
import validators
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

# initialize the Flask app and SQLAlchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///url.db'
db = SQLAlchemy(app)


class Url(db.Model):
    # create the relevant columns
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(100))
    hash = db.Column(db.String(100))

    # function to hash the value
    def hash_value(self):
        hasher = hashlib.sha256()
        hasher.update(self.value.encode('utf-8'))
        return hasher.hexdigest()[:4]


with app.app_context():
    db.create_all()


# create the POST route to add new URLs to the database
@app.route('/', methods=['POST'])
def create():
    value = request.json['value']
    # check if the value matches a URL format

    # if not re.match(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+$', value):
    #     return jsonify({'error': 'Invalid URL format'}), 400

    if validators.url(value):
        hashed_value = Url(value=value).hash_value()
        url = Url(value=value, hash=hashed_value)
        db.session.add(url)
        db.session.commit()
        return jsonify({'id': url.id, 'value': url.hash}), 201
    else:
        return jsonify({'error': 'Invalid URL format'}), 400

# create the PUT route to update an existing URL
@app.route('/<int:id>', methods=['PUT'])
def update(id):
    url = Url.query.get(id)
    if not url:
        return jsonify({'message': 'Url not found'}), 404
    value = request.json['value']
    # check if the value matches a URL format

    # if not re.match(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+$', value):
    #     return jsonify({'error': 'Invalid URL format'}), 400

    if validators.url(value):
        hashed_value = Url(value=value).hash_value()
        url.value = value
        url.hash = hashed_value
        db.session.commit()
        return jsonify({'id': url.id, 'value': url.hash})
    else:
        return jsonify({'error': 'Wrong URL format'}), 400

# create the GET route to get all URLs from the database
@app.route('/', methods=['GET'])
def get_all():
    urls = Url.query.all()
    output = []
    for url in urls:
        output.append({'id': url.id, 'value': url.hash})
    return jsonify({'urls': output})


# create the GET route to get one URL by id from the database
@app.route('/<int:id>', methods=['GET'])
def get_one(id):
    url = Url.query.get(id)
    if not url:
        return jsonify({'message': 'Url not found'}), 404
    return jsonify({'id': url.id, 'value': url.hash})


# create the DELETE route to delete all URLs from the database
@app.route('/', methods=['DELETE'])
def delete():
    urls = Url.query.all()
    if not urls:
        return jsonify({'message': 'Url not found'}), 404
    for url in urls:
        db.session.delete(url)
    db.session.commit()
    return '', 204


# create the DELETE route to delete one URL from the database
@app.route('/<int:id>', methods=['DELETE'])
def delete_one(id):
    url = Url.query.get(id)
    if not url:
        return jsonify({'message': 'Url not found'}), 404
    db.session.delete(url)
    db.session.commit()
    return '', 204


if __name__ == '__main__':
    app.run(debug=True)
