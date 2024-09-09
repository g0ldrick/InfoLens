import streamlit as st
from streamlit_lottie import st_lottie
import requests
from pymongo import MongoClient
import bcrypt
import logging
logging.basicConfig(level=logging.DEBUG)


#---------------------------- Secrets Management ----------------------------#

# important to manage secrets correctly otherwise unauthorised access to database etc

username = st.secrets["mongo"]["username"]
password = st.secrets["mongo"]["password"]
cluster_url = st.secrets["mongo"]["cluster_url"]
db_name = st.secrets["mongo"]["db_name"]

MONGO_URI = f"mongodb+srv://{username}:{password}@{cluster_url}/{db_name}?retryWrites=true&w=majority"



# Create a new client and connect to the server
client = MongoClient(MONGO_URI)
# Access the database and collection
db = client["infolens_db"]
users_collection = db["users"]

# Function to hash the password for sign up
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Function to verify the password in login
def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

# Function to load Lottie animations from hosted URL
def load_lottie_url(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_animation = load_lottie_url("https://lottie.host/ad806642-171f-4e41-a64d-40484a01631f/vSiDkHmxzU.json")

def home():
    '''Home page to display information on how to use and navigate the application to end-user'''
    if "message" in st.session_state and st.session_state["message"]:
        if "logged out" in st.session_state["message"].lower():
            st.error(st.session_state["message"])  # logout message in red
        else:
            st.success(st.session_state["message"])  # other messages in green
        st.session_state["message"] = ""  # clear message on next navigation 
    st.title("Welcome to InfoLens!")
    st.write("""
        Welcome to InfoLens, a powerful tool for disinformation detection designed to empower the individual 
        by helping you to assess the veracity of textual content you may find online. With the now ubiquitous
        nature of both mis- and disinformation, you should be more skeptical than ever at taking information 
        you come across online at face value! \n
    """)
    st_lottie(lottie_animation, height=300, key="disinformation_animation")
    st.write("""Use the navigation bar on the left to explore different features of the application, sign up
        for an account and log in if you wish to make predictions on text.""")

def predict():
    '''Main page for text input from user and prediction to be displayed'''
    st.title("InfoLens: Disinformation Detector")
    user_input = st.text_area("Enter news article or statement for analysis here:")
    if st.button("Classify"):
        st.write("Processing text...")
        st.write("Result: implementation of prediction models not complete. Try again soon!")

# Sign up page
def signup():
    st.title("Sign Up")

    first_name = st.text_input("First Name")
    email = st.text_input("Email (Username)")
    password = st.text_input("Password", type="password")

    if st.button("Sign Up"):
        if users_collection.find_one({"email": email}):
            st.error("An account with this email already exists.")
        else:
            new_user = {
                "name": first_name,
                "email": email,
                "password": hash_password(password)  # hash password for storage
            }
            users_collection.insert_one(new_user)
            st.session_state["message"] = f"Signed up successfully as {first_name}!"
            st.session_state.logged_in = True
            st.session_state.current_page = "Home"
            st.rerun()

# Log in page
def login():
    st.title("Log In")

    email = st.text_input("Email (Username)")
    password = st.text_input("Password", type="password")

    if st.button("Log In"):
        # Check if user exists in db
        user = users_collection.find_one({"email": email})
        
        if user:
            # verify provided password
            if verify_password(user["password"], password):
                st.session_state.logged_in = True
                st.session_state.current_page = "Home"
                st.session_state["message"] = f"Logged in as {user['name']}!"
                st.rerun()  # reload app
            else:
                st.error("Incorrect password.")
        else:
            st.error("User not found.")

def main():
    '''Main method for rendering the current page and handling navigation between pages.'''

    # Initialize session state for logging in
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "message" not in st.session_state:
        st.session_state["message"] = ""

    # Setting default session to be home
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Home"

    # Navigation between pages handled here along with persisting sessions based on selected page.
    st.sidebar.title("Navigation")

    # home page always accessible
    if st.sidebar.button("Home", key="home_button"):
        st.session_state.current_page = "Home"

    # page handling - only show predict when logged in, sign up and log in when not logged in
    # log out only shows when logged in.
    if st.session_state.logged_in:
        if st.sidebar.button("Predict"):
            st.session_state.current_page = "Predict"
        if st.sidebar.button("Log Out", key="logout_button"):
            st.session_state.logged_in = False
            st.session_state.current_page = "Home"
            st.session_state["message"] = "Logged out successfully!"
            st.rerun()  # Force page reload upon logout
    else:
        if st.sidebar.button("Log In", key="login_button_sidebar"):
            st.session_state.current_page = "Log In"
        if st.sidebar.button("Sign Up", key="signup_button_sidebar"):
            st.session_state.current_page = "Sign Up"

    # display page based on the current session state
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
