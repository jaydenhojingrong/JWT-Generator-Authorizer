import ast
import base64
import json
import time
from flask import Flask, request, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS 
import boto3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:password@itsa-dev.cwp8u9nj29mg.ap-southeast-1.rds.amazonaws.com"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

CORS(app)

class Users(db.Model):
    __tablename__ = 'Users'

    id = db.Column(db.String(), primary_key=True)
    first_name = db.Column(db.String(), nullable=True)
    last_name = db.Column(db.String(), nullable=True)
    email = db.Column(db.String(), nullable=True)
    birthday = db.Column(db.String(), nullable=True)
    status = db.Column(db.String(), nullable=True)
    role = db.Column(db.String(), nullable=True)

    def __init__(self, id, first_name, last_name, email, birthday, status, role):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.birthday = birthday
        self.status = status
        self.role = role

    def json(self):
        return {"id": self.id, "first_name": self.first_name, "last_name": self.last_name, "email": self.email, "birthday": self.birthday, "status": self.status, "role": self.role}

@app.route("/")
def healthcheck():
    return Response("200", status=200, mimetype='application/json')

@app.route('/generate_token/<string:email>')
def generate_token(email):

    role =  str()
    response = find_by_email(email)
    role = (ast.literal_eval(response.data.decode('utf-8')))["data"]["role"]

    iat = int(time.time() )
    exp = (iat + (15 * 60))
    kid = "0f00b1e6-10c0-457b-8544-6e1712c0adf3"

    headers={
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
        "iss": "https://g2t5.com"
    }

    payload = {
        "email": email,
        "iat": iat,
        "exp": exp,
        "aud": "https://g2t5.com",
        "scope": "openid " + role
    }

    token_components = {
        "headers":  base64.urlsafe_b64encode(json.dumps(headers).encode()).decode().rstrip("="),
        "payload": base64.urlsafe_b64encode(json.dumps(payload, indent=4, sort_keys=True, default=str).encode()).decode().rstrip("="),
    }
    message = f'{token_components.get("headers")}.{token_components.get("payload")}'

    kms_client = boto3.client("kms")
    response = kms_client.sign(
        KeyId=kid, 
        Message=message.encode(), 
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256", 
        MessageType="RAW"
    )
    token_components["signature"] = base64.urlsafe_b64encode(response["Signature"]).decode().rstrip("=")
    return f'{token_components.get("headers")}.{token_components.get("payload")}.{token_components["signature"]}'

@app.route("/users")
def get_all():
    userList = Users.query.all()
    if len(userList):
        return jsonify ({
            "code": 200,
            "data": {
                "users": [user.json() for user in userList]
            }
        })
    return jsonify({
        "code": 404,
        "message":"There are no users"
    })


@app.route("/user/<string:email>")
def find_by_email(email):
    user = Users.query.filter_by(email=email).first()
    if user:
        return jsonify(
            {
                "code": 200,
                "data": user.json()
            }
        )
    return jsonify(
        {
            "code": 404,
            "message": "User not found."
        }
    ), 404


@app.route("/user/<string:email>", methods=['POST'])
def create_user(email):
    if (Users.query.filter_by(email=email).first()):
        return jsonify(
            {
                "code": 400,
                "data": {
                    "email": email
                },
                "message": "User already exists."
            }
        ), 400

    data = request.get_json()
    user = Users(email=email, **data)

    try:
        db.session.add(user)
        db.session.commit()
    except:
        return jsonify(
            {
                "code": 500,
                "data": {
                    "email": email
                },
                "message": "An error occurred creating the user."
            }
        ), 500

    return jsonify(
        {
            "code": 201,
            "data": user.json()
        }
    ), 201

@app.route("/user/<string:email>", methods=['DELETE'])
def delete_user(email):
    user = Users.query.filter_by(email=email).first()

    if user:
        Users.query.filter_by(email=email).delete()
        db.session.commit()
        return ({
            "code": 200,
            "data": user.json()
        })
    else:
        return ({
            "code": 400,
            "message": "User does not exist"
        })

@app.route("/user/<string:email>", methods=['PUT'])
def update_user(email):
    userExist = Users.query.filter_by(email=email).first()

    if userExist:

        data = request.get_json()
        
        try:
            userExist.first_name = data["first_name"]
            userExist.last_name = data["last_name"]
            userExist.birthday = data["birthday"]
            userExist.status = data["status"]
            db.session.commit()

            return jsonify(
                {
                    "code": 201,
                    "data": userExist.json()
                }
            ), 201

        except:
            return jsonify(
            {
                "code": 500,
                "message": "Error occurred while updating the user record"
            }
        ), 500
    else:
        return ({
            "code": 400,
            "message": "User does not exist"
        })
        
if __name__ == '__main__':
    app.run(port=5000, debug=True, host='0.0.0.0')