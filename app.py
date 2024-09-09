# app.py
import streamlit as st
from streamlit_lottie import st_lottie
import requests
from backend import connect_to_db, add_user, authenticate_user

# Function to load Lottie animations from hosted URL
def load_lottie_url(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_animation = load_lottie_url("https://lottie.host/ad806642-171f-4e41-a64d-40484a01631f/vSiDkHmxzU.json")

# Connect to the MongoDB database
db = connect_to_db()

def home():
    '''Home page to display information on how to use and navigate the application to end-user'''
    if "message" in st.session_state and st.session_state["message"]:
        if "logged out" in st.session_state["message"].lower():
            st.error(st.session_state["message"])  # logout message in red
        else:
            st.success(st.session_state["message"])  # other messages in green
        st.session_state["message"] = ""  # clear message on next page navigation

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

    # Place the buttons with minimal space between them
    col1, col2 = st.columns([1, 1])
    
    with col1:
        if st.button("Sign Up"):
            st.session_state.current_page = "Sign Up"
            st.rerun()

    with col2:
        if st.button("Log In"):
            st.session_state.current_page = "Log In"
            st.rerun()

def signup():
    st.title("Sign Up")

    first_name = st.text_input("First Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Sign Up"):
        success, message = add_user(db, first_name, email, password)
        if success:
            st.session_state["message"] = message
            st.session_state.logged_in = True
            st.session_state.current_page = "Home"
            st.rerun()
        else:
            st.error(message)

def login():
    st.title("Log In")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Log In"):
        success, message = authenticate_user(db, email, password)
        if success:
            st.session_state["message"] = f"Logged in as {message}"
            st.session_state.logged_in = True
            st.session_state.current_page = "Home"
            st.rerun()
        else:
            st.error(message)

def main():
    '''Main method for rendering the current page and handling navigation between pages.'''

    # Initialize session state for logging in
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "message" not in st.session_state:
        st.session_state["message"] = ""

    # Setting default session to be the home page.
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Home"

    # Navigation between pages handled here along with persisting sessions based on selected page.
    st.sidebar.title("Navigation")

    if st.sidebar.button("Home", key="home_button"):
        st.session_state.current_page = "Home"

    # Only show Predict, Log In, Sign Up when appropriate
    if st.session_state.logged_in:
        if st.sidebar.button("Predict"):
            st.session_state.current_page = "Predict"
        if st.sidebar.button("Log Out", key="logout_button"):
            st.session_state.logged_in = False
            st.session_state.current_page = "Home"
            st.session_state["message"] = "Logged out successfully!"
            st.rerun()
    else:
        if st.sidebar.button("Log In", key="login_button_sidebar"):
            st.session_state.current_page = "Log In"
        if st.sidebar.button("Sign Up", key="signup_button_sidebar"):
            st.session_state.current_page = "Sign Up"

    # Display the correct page based on the current session state
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
