import streamlit as st
from streamlit_lottie import st_lottie
import requests
import bcrypt
from pymongo import MongoClient
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from streamlit_cookies_manager import EncryptedCookieManager

# Create a Cookie Manager
cookies = EncryptedCookieManager(password="your_secret_password")  # Replace with your password

if not cookies.ready():
    st.stop()

# Function to load Lottie animations from hosted URL
def load_lottie_url(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_animation = load_lottie_url("https://lottie.host/ad806642-171f-4e41-a64d-40484a01631f/vSiDkHmxzU.json")

# Connect to MongoDB
def connect_to_db():
    username = st.secrets["mongo"]["username"]
    password = st.secrets["mongo"]["password"]
    cluster_url = st.secrets["mongo"]["cluster_url"]
    db_name = st.secrets["mongo"]["db_name"]

    mongo_uri = f"mongodb+srv://{username}:{password}@{cluster_url}/{db_name}?retryWrites=true&w=majority"
    client = MongoClient(mongo_uri)
    db = client[db_name]
    return db

# Hash the password for sign up
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Verify the password during login
def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

# Add a new user to the database
def add_user(db, first_name, email, password):
    users_collection = db["users"]
    if users_collection.find_one({"email": email}):
        return False, "An account with this email already exists."
    
    new_user = {
        "name": first_name,
        "email": email,
        "password": hash_password(password),
        "confirmed": False  # Email confirmation status
    }
    users_collection.insert_one(new_user)
    return True, "Signed up successfully! Please confirm your email."

# Authenticate an existing user
def authenticate_user(db, email, password):
    users_collection = db["users"]
    user = users_collection.find_one({"email": email})

    if not user["confirmed"]:
        return False, "Please confirm your email address before logging in."
    
    if user and verify_password(user["password"], password):
        return True, user["name"]
    
    return False, "Invalid email or password."

# Email validation using AbstractAPI
def validate_email_api(email):
    api_key = st.secrets["abstractapi"]["api_key"]
    url = f"https://emailvalidation.abstractapi.com/v1/?api_key={api_key}&email={email}"

    response = requests.get(url)
    data = response.json()

    if 'is_valid_format' in data and data['is_valid_format']['value']:
        return True
    else:
        return False

# Configure Flask-Mail for sending emails
def configure_email():
    mail = Mail()
    mail.server = st.secrets["email"]["smtp_server"]
    mail.port = st
