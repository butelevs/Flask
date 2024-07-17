import pydantic
from flask import Flask, jsonify, request
from flask.views import MethodView
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError

from models import Session, Advertisement, User
from schema import CreateAdvertisement, CreateUser


app = Flask('advertisements_app')
bcrypt = Bcrypt(app)


class HttpError(Exception):
    def __init__(self, status_code: int, description: str):
        self.status_code = status_code
        self.description = description

@app.errorhandler(HttpError)
def error_handler(error: HttpError):
    response = jsonify({'error': error.description})
    response.status_code = error.status_code
    return response


@app.before_request
def before_request():
    session = Session()
    request.session = session

@app.after_request
def after_request(response):
    request.session.close()
    return response


def hash_password(password: str):
    password = password.encode()
    return bcrypt.generate_password_hash(password).decode()


def get_advertisement_by_id(advertisement_id: int) -> Advertisement:
    advertisement = request.session.get(Advertisement, advertisement_id)
    if advertisement is None:
        raise HttpError(404, 'Advertisement not found')
    return advertisement


def get_user_by_id(user_id: int) -> User:
    user = request.session.get(User, user_id)
    if user is None:
        raise HttpError(404, "user not found")
    return user


def validate(schema_class, json_data):
    try:
        return schema_class(**json_data).dict(exclude_unset=True)
    except pydantic.ValidationError as err:
        error = err.errors()[0]
        error.pop('ctx', None)
        raise HttpError(400, error)

def add_advertisement(advertisement: Advertisement):
    try:
        request.session.add(advertisement)
        request.session.commit()
    except IntegrityError as err:
        raise HttpError(409, 'advertisement already exists')
    return advertisement


def add_user(user: User):
    try:
        request.session.add(user)
        request.session.commit()
    except IntegrityError as err:
        raise HttpError(409, 'user already exists')
    return user


class AdvertisementView(MethodView):
    def get(self, advertisement_id: int):
        advertisement = get_advertisement_by_id(advertisement_id)
        return jsonify(advertisement.json)

    def post(self):
        json_data = validate(CreateAdvertisement, request.json)
        advertisement = Advertisement(**json_data)
        add_advertisement(advertisement)
        response = jsonify(advertisement.json)
        response.status_code = 201
        return response

    def delete(self, advertisement_id: int):
        advertisement = get_advertisement_by_id(advertisement_id)
        user_id = int(request.headers['User'])
        if advertisement.owner_id != user_id:
            raise HttpError(403, 'Only owner can delete advertisement')
        user = get_user_by_id(user_id)
        if not bcrypt.check_password_hash(user.password, request.headers['password']):
            raise HttpError(403, 'Invalid password')
        request.session.delete(advertisement)
        request.session.commit()
        return jsonify({'status': 'success'})


class UserView(MethodView):
    def get(self, user_id: int):
        user = get_user_by_id(user_id)
        return jsonify(user.json)
    
    def post(self):
        json_data = validate(CreateUser, request.json)
        json_data['password'] = hash_password(json_data['password'])
        user = User(**json_data)
        add_user(user)
        response = jsonify(user.json)
        response.status_code = 201
        return response

    def delete(self, user_id: int):
        user = get_user_by_id(user_id)
        request.session.delete(user)
        request.session.commit()
        return jsonify({'status': 'success'})


advertisement_view = AdvertisementView.as_view('advertisement_view')
user_view = UserView.as_view('user_view')

app.add_url_rule(
    '/adverstisements',
    view_func=advertisement_view,
    methods=[
        'POST',
    ]
)

app.add_url_rule(
    '/adverstisements/<int:advertisement_id>',
    view_func=advertisement_view,
    methods=[
        'GET',
        'DELETE'
    ]
)

app.add_url_rule(
    '/users',
    view_func=user_view,
    methods=[
        'POST',
    ],
)
app.add_url_rule(
    '/users/<int:user_id>', 
    view_func=user_view, 
    methods=[
        'GET',
        'DELETE'
    ]
)


app.run()