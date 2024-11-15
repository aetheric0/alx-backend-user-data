#!/usr/bin/env python3
""" View to handle Session authentication
"""
from . import app_views
from models.user import User
from os import getenv
from flask import request, jsonify, make_response


@app_views.route('/auth_session/login', methods=['POST'],
                 strict_slashes=False)
def session_auth():
    """ Handles the Session authentication routes
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if email is None:
        return jsonify({'error': 'email missing'}), 400
    if password is None:
        return jsonify({'error': 'password missing'}), 400
    user_class = User()
    user_list = user_class.search({'email': email})
    if len(user_list) == 1:
        db_user = user_list[0]
    else:
        return jsonify({'error': 'no user found for this email'}), 404
    if not db_user.is_valid_password(password):
        return jsonify({'error': 'wrong password'}), 401

    from api.v1.app import auth
    session_id = auth.create_session(db_user.id)
    print(session_id)
    user_dict = db_user.to_json()
    resp = make_response(user_dict)
    cookie_name = getenv('SESSION_NAME')
    resp.set_cookie(cookie_name, session_id)
    return resp


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout_session():
    from api.v1.app import auth
    destroy_status = auth.destroy_session(request)
    if destroy_status:
        return jsonify({}), 200
    return abort(404)
