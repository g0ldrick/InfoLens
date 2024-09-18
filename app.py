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
    mail.port = st.secrets["email"]["smtp_port"]
    mail.use_tls = True
    mail.username = st.secrets["email"]["username"]
    mail.password = st.secrets["email"]["password"]
    return mail

# Generate confirmation token
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer("your_secret_key")
    return serializer.dumps(email, salt="email-confirm-salt")

# Send confirmation email
def send_confirmation_email(user_email):
    mail = configure_email()
    token = generate_confirmation_token(user_email)
    confirm_url = f"https://yourapp.com/confirm/{token}"

    msg = Message("Confirm Your Email Address", sender=st.secrets["email"]["username"], recipients=[user_email])
    msg.body = f"Hi! Please confirm your email address by clicking this link: {confirm_url}"
    mail.send(msg)

# Confirm email from token
def confirm_email(token):
    try:
        serializer = URLSafeTimedSerializer("your_secret_key")
        email = serializer.loads(token, salt="email-confirm-salt", max_age=3600)  # 1 hour expiry
        db = connect_to_db()
        db["users"].update_one({"email": email}, {"$set": {"confirmed": True}})
        st.success("Email confirmed successfully!")
    except SignatureExpired:
        st.error("The confirmation link has expired.")
    except BadSignature:
        st.error("Invalid confirmation link.")

# Check if user is logged in based on cookies
def check_login():
    # Retrieve session state from cookies
    logged_in = cookies.get("logged_in")
    user_name = cookies.get("user_name")

    if logged_in == "True":
        st.session_state.logged_in = True
        st.session_state.user_name = user_name
    else:
        st.session_state.logged_in = False

# Main app navigation and session state
def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "message" not in st.session_state:
        st.session_state["message"] = ""

    if "current_page" not in st.session_state:
        st.session_state.current_page = "Home"

    # Check if user is logged in using cookies
    check_login()

    st.sidebar.title("Navigation")

    if st.sidebar.button("Home", key="home_button_sidebar"):
        st.session_state.current_page = "Home"

    if st.session_state.logged_in:
        if st.sidebar.button("Predict", key="predict_button_sidebar"):
            st.session_state.current_page = "Predict"
        if st.sidebar.button("Log Out", key="logout_button_sidebar"):
            clear_login_session()  # Clear session on log out
            st.session_state.current_page = "Home"
            st.session_state["message"] = "Logged out successfully!"
            st.rerun()
    else:
        if st.sidebar.button("Log In", key="login_button_sidebar"):
            st.session_state.current_page = "Log In"
        if st.sidebar.button("Sign Up", key="signup_button_sidebar"):
            st.session_state.current_page = "Sign Up"

    # Display the appropriate page
    if st.session_state.current_page == "Home":
        home()
    elif st.session_state.current_page == "Predict" and st.session_state.logged_in:
        predict()
    elif st.session_state.current_page == "Log In" and not st.session_state.logged_in:
        login()
    elif st.session_state.current_page == "Sign Up" and not st.session_state.logged_in:
        signup()

# Home page content
def home():
    st.title("Welcome to InfoLens!")
    st.write("This app detects disinformation. Use the navigation bar to sign up or log in.")
    st_lottie(lottie_animation, height=300, key="disinformation_animation")

# Prediction page
def predict():
    st.title("Make a Prediction")
    user_input = st.text_area("Enter text to analyze", placeholder="Type your text here...")

    if st.button("Classify", key="classify_button"):
        if user_input:
            result = make_prediction_via_api(user_input)
            if result == 1:
                st.write("Response from our classification model indicates that this information is **FALSE**.")
            elif result == 0:
                st.write("Response from our classification model indicates that this information is **TRUE**.")
        else:
            st.warning("Please enter some text before clicking Classify.")

# Signup page
def signup():
    st.title("Sign Up")

    first_name = st.text_input("First Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Sign Up", key="signup_button"):
        if not validate_email_api(email):
            st.error("Please enter a valid email address.")
        else:
            db = connect_to_db()
            success, message = add_user(db, first_name, email, password)
            if success:
                send_confirmation_email(email)
                st.success("Confirmation email sent. Please check your inbox.")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error(message)

# Login page
def login():
    st.title("Log In")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Log In", key="login_button"):
        db = connect_to_db()
        success, user_name = authenticate_user(db, email, password)
        if success:
            st.session_state["message"] = f"Logged in as {user_name}"
            st.session_state.logged_in = True
            st.session_state.current_page = "Home"
            st.rerun()
        else:
            st.error(user_name)

# Function to make API requests to your Cloud Run API
def make_prediction_via_api(text, model="cnn"):
    api_url = "https://infolens-ml-api-3vvr7n346a-nw.a.run.app/predict"
    payload = {"text": text, "model": model}
    try:
        response = requests.post(api_url, json=payload)
        response.raise_for_status()
        result = response.json().get("prediction", "Unknown")
        return result
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    main()
