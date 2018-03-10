#!/usr/bin/env python
from sqlalchemy import create_engine
from flask_jsonpify import jsonpify
from flask import Flask

import logging
import hashlib
import uuid
import sys

conn = create_engine('sqlite:///Users.db').connect()
app = Flask(__name__)
salt = uuid.uuid4().hex


def hash_password(password):
    hashed = hashlib.sha512(password + salt).hexdigest()
    return hashed


def does_email_exist(email):
    exists = False
    ask_database = conn.execute('select * from MainInfo where Email="{0}"'.format(email))
    check_empty = ask_database.cursor.fetchall()
    if check_empty:
        exists = True
    return exists


def validate_password(password, email):
    valid_password = False
    ask_database = conn.execute('select * from MainInfo where Email="{0}" and Password="{1}"'.format(email, hash_password(password)))
    check_empty = ask_database.cursor.fetchall()
    if check_empty:
        valid_password = True
    return valid_password


def check_admin(email):
    ask_database = conn.execute('select * from MainInfo where Email="{0}" and is_admin=1'.format(email))
    check_empty = ask_database.cursor.fetchall()
    print check_empty
    if check_empty is not None:
        is_admin = True
        logging.info("admin verified")
        return is_admin
    else:
        is_admin = False
        return is_admin


# BELOW ARE THE ENPOINTS THAT ONLY ADMINS SHOULD BE ALLOWED TO USE
# TODO CREATE A ADMIN PASSWORD THAT CAN BE USED TO PASS INTO THE ENDPOINT FOR VERIFICATION
# This will return all users from the database
@app.route("/display_all_users/<admin_email>/<admin_password>", methods=["GET"])
def display_all_users(admin_email, admin_password):
    is_email_admin = check_admin(admin_email)
    if is_email_admin is True:
        is_password_valid = validate_password(admin_password, admin_email)
        if is_password_valid is True:
            query = conn.execute('select * from MainInfo')
            result = {'data': [dict(zip(tuple(query.keys()), i)) for i in query.cursor]}
            return jsonpify(result)
        else:
            logging.warning("BAD MAN: You are not an admin")
            return "Not an admin"
    else:
        logging.warning("BAD MAN: You are not an admin")
        return "Not an admin"


# get data based on the unique email provided
@app.route("/display_users/<email>/<admin_email>/<admin_password>", methods=["GET"])
def display_specific_user(email, admin_email, admin_password):
    is_email_admin = check_admin(admin_email)
    i_exist = does_email_exist(email)
    if i_exist:
        query = conn.execute('select * from MainInfo where Email="{0}"'.format(email))
        result = {'data': [dict(zip(tuple(query.keys()), i)) for i in query.cursor]}
        return jsonpify(result)
    else:
        logging.warning("No user found with that email")
        return "No email"


# add new user into the database based on the parameters provided
@app.route("/create_user/<username>/<email>/<password>/<is_admin>", methods=["GET"])
def create_user(username, email, password, is_admin):

    conn.execute('insert into MainInfo values("{0}", "{1}", "{2}", "{3}");'.format(username, email, hash_password(password), is_admin))
    logging.info("User created with email: {0} and username: {1}".format(email, username))
    return "data entered"


# delete a user given their email address
@app.route("/delete_user/<email>", methods=["GET"])
def delete_user(email):
    valid_email = does_email_exist(email)
    if valid_email:
        conn.execute('delete from MainInfo where Email="{0}"'.format(email))
        logging.info("User: {0} Deleted".format(email))
        return "User deleted"
    else:
        logging.warning("Invalid user for deletion")
        return "User doesn't exist for deletion"


# BELOW ARE THE USER AUTHENTICATED CHANGES, THESE ARE THE ONLY CHANGES A USER SHOULD BE ABLE TO MAKE
# For security I am forcing them to authenticate with their password everytime or the old password
# TODO is there a better way to do this really? not sure


# Endpoint Changes email given the current password of the user
@app.route("/change_email/<password>/<old_email>/<new_email>", methods=["GET"])
def change_user_email(password, old_email, new_email):
    vaild_email = does_email_exist(old_email)
    valid_password = validate_password(password, old_email)
    if vaild_email and valid_password:
        conn.execute('update MainInfo set Email="{0}" where Email="{1}" and Password="{2}" '.format(new_email, old_email, hash_password(password)))
        logging.info("Email changed\nFrom: {0}\nTo:".format(old_email, new_email))
        return "Users email changed"
    else:
        logging.warning("Email or password were not valid")
        return "Invalid email or password"


# Endpoint changes users password given old and new
@app.route("/change_password/<old_password>/<new_password>/<email>", methods=["GET"])
def change_user_password(old_password, new_password, email):
    valid_email = does_email_exist(email)
    valid_password = validate_password(old_password)
    if valid_email and valid_password:
        conn.execute('update MainInfo set Password="{0}" where Email="{1}" and Password="{2}" '.format(hash_password(new_password), hash_password(old_password), email))
        logging.info("Changed password for User: {0}".format(email))
        return "password changed"
    else:
        logging.warning("Invalid email or password")
        return "Invalid email or password"


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    app.run(host='0.0.0.0', debug=True)
