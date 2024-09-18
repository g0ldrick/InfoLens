# app.py
import streamlit as st
from streamlit_lottie import st_lottie
import requests
import bcrypt
from pymongo import MongoClient
from streamlit_cookies_manager import EncryptedCookieManager

# Create a Cookie Manager
cookies = EncryptedCookieManager(
    password="your_secret_password",  # You should change this password
)

if not cookies.ready():
    st.stop()

# Function to load Lottie animations from a hosted URL
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
        "password": hash_password(password)
    }
    users_collection.insert_one(new_user)
    return True, "Signed up successfully!"

# Authenticate an existing user
def authenticate_user(db, email, password):
    users_collection = db["users"]
    user = users_collection.find_one({"email": email})
    
    if user and verify_password(user["password"], password):
        return True, user["name"]
    
    return False, "Invalid email or password."

# Function to make API requests to your Cloud Run API
def make_prediction_via_api(text, model="cnn"):
    api_url = "https://infolens-ml-api-3vvr7n346a-nw.a.run.app/predict"
    payload = {
        "text": text,
        "model": model  # You can change model if needed
    }
    try:
        response = requests.post(api_url, json=payload)
        response.raise_for_status()
        result = response.json().get("prediction", "Unknown")
        return result
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

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

# Set login session and store in cookies
def set_login_session(user_name):
    st.session_state.logged_in = True
    st.session_state.user_name = user_name
    cookies["logged_in"] = "True"
    cookies["user_name"] = user_name
    cookies.save()

# Clear login session
def clear_login_session():
    st.session_state.logged_in = False
    st.session_state.user_name = ""
    cookies["logged_in"] = "False"
    cookies["user_name"] = ""
    cookies.save()

# Home page content
def home():
    if "message" in st.session_state and st.session_state["message"]:
        if "logged out" in st.session_state["message"].lower():
            st.error(st.session_state["message"])  # logout message in red
        else:
            st.success(st.session_state["message"])  # other messages in green
        st.session_state["message"] = ""  # clear message on next page navigation

    st.title("Welcome to InfoLens!")
    st.write("""
        Welcome to InfoLens, a powerful tool for disinformation detection designed to empower individuals 
        by helping you assess the veracity of textual content you find online. In the era of pervasive
        misinformation and disinformation, it's important to evaluate the truthfulness of what you read online.\n
    """)
    st_lottie(lottie_animation, height=300, key="disinformation_animation")
    st.write("""Use the navigation bar on the left to explore different features of the application. 
        You can sign up for an account or log in to make predictions on textual content.""")

# Prediction page
def predict():
    st.title("Make a Prediction")

    # Text area for user to input the text for prediction
    user_input = st.text_area("Enter text to analyze", placeholder="Type your text here...")

    if st.button("Classify", key="classify_button"):
        if user_input:  # Check if input is not empty
            result = make_prediction_via_api(user_input)  # Call the API for prediction
            st.write(f"Prediction: {result}")
        else:
            st.warning("Please enter some text before clicking Classify.")

# Signup page
def signup():
    st.title("Sign Up")

    first_name = st.text_input("First Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Sign Up", key="signup_button"):
        db = connect_to_db()
        success, message = add_user(db, first_name, email, password)
        if success:
            st.session_state["message"] = message
            set_login_session(first_name)  # Set login session for the new user
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
            set_login_session(user_name)  # Set login session
            st.session_state.current_page = "Home"
            st.rerun()
        else:
            st.error(user_name)

# Main function to handle navigation and session state
def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "message" not in st.session_state:
        st.session_state["message"] = ""

    if "current_page" not in st.session_state:
        st.session_state.current_page = "Home"

    # Check login session in cookies
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

if __name__ == "__main__":
    main()
