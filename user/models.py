import re
from flask import Flask, jsonify, request
import uuid
from passlib.hash import pbkdf2_sha256
import pymongo

#Database
client = pymongo.MongoClient("localhost", 27017)
db = client.user_login_info

#Create User
class User:

    def get_id(self):
        user = db.user.find_one({"email": request.form.get("email") })
        return user["_id"]

    def user_exist(self):
        if db.user.find_one({"email": request.form.get("email") }):
            return True
        return False

    def login(self):
        user = db.user.find_one({"email": request.form.get("email") })
        
        if user and pbkdf2_sha256.verify(request.form.get("password"), user["password"]):
            return True
        return False

    def signup(self):

        user = {
            "_id":uuid.uuid4().hex,
            "name":request.form.get("name"),
            "email":request.form.get("email"),
            "password":request.form.get("password")     
        }

        #Encrypt password
        user["password"] = pbkdf2_sha256.encrypt(user["password"])

        db.user.insert_one(user)

        return jsonify(user), 200