"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
import bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
api = Blueprint('api', __name__)




@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/user/register', methods=['POST'])
def register():
    body = request.get_json()
    hashed = bcrypt.hashpw(body['password'].encode(),bcrypt.gensalt(14))
    new_user = User(email = body['email'], password = hashed.decode(), is_active =True)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(new_user.serialize()), 201

@api.route('/user/login', methods=['POST'])
def login():
    body = request.get_json()
    user = User.query.filter_by( email = body['email']).one()
    if bcrypt.checkpw(body['password'].encode(),user.password.encode()):
        create_token = create_access_token(identity = user.serialize())
        return jsonify(create_token),200
    else:
        return jsonify('no login')

@api.route('/user/<int:id>', methods=['GET'])
@jwt_required()
def get_user_id(id):
    user = User.query.get(id)
    return jsonify(user.serialize()), 201