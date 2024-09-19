import streamlit as st
from streamlit_lottie import st_lottie
import requests
import bcrypt
from pymongo import MongoClient
from flask import Flask
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from streamlit_cookies_manager import EncryptedCookieManager
import datetime


app = Flask(__name__)


cookies = EncryptedCookieManager(password=st.secrets["app-secrets"]["secret_password"])

if not cookies.ready():
    st.stop()


def load_lottie_url(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_animation = load_lottie_url("https://lottie.host/ad806642-171f-4e41-a64d-40484a01631f/vSiDkHmxzU.json")


def connect_to_db():
    username = st.secrets["mongo"]["username"]
    password = st.secrets["mongo"]["password"]
    cluster_url = st.secrets["mongo"]["cluster_url"]
    db_name = st.secrets["mongo"]["db_name"]

    mongo_uri = f"mongodb+srv://{username}:{password}@{cluster_url}/{db_name}?retryWrites=true&w=majority"
    client = MongoClient(mongo_uri)
    db = client[db_name]
    return db


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)


def add_user(db, first_name, email, password):
    users_collection = db["users"]
    if users_collection.find_one({"email": email}):
        return False, "An account with this email already exists."
    
    new_user = {
        "name": first_name,
        "email": email,
        "password": hash_password(password),
        "confirmed": False 
    }
    users_collection.insert_one(new_user)
    return True, "Signed up successfully! Please confirm your email."


def authenticate_user(db, email, password):
    users_collection = db["users"]
    user = users_collection.find_one({"email": email})

    if not user:  # Check if user exists
        return False, "User does not exist."

    if not user["confirmed"]:
        return False, "Please confirm your email address before logging in."
    
    if verify_password(user["password"], password):
        return True, user["name"]
    
    return False, "Invalid email or password."


def validate_email_api(email):
    api_key = st.secrets["abstractapi"]["api_key"]
    url = f"https://emailvalidation.abstractapi.com/v1/?api_key={api_key}&email={email}"

    try:
        response = requests.get(url)
        data = response.json()

        
        if (data.get('deliverability') == 'DELIVERABLE' and
            data.get('is_smtp_valid', {}).get('value') and 
            data.get('is_mx_found', {}).get('value')):
            return True
        else:
            st.error(f"Invalid email address: {data.get('email')} is not deliverable.")
            return False
    except Exception as e:
        st.error(f"Email validation failed: {e}")
        return False


def configure_email():
    app.config['MAIL_SERVER'] = st.secrets["email"]["smtp_server"]
    app.config['MAIL_PORT'] = st.secrets["email"]["smtp_port"]
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = st.secrets["email"]["username"]
    app.config['MAIL_PASSWORD'] = st.secrets["email"]["password"]
    
    mail = Mail(app)
    return mail


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(st.secrets["app-secrets"]["secret_key"])  # Using the secret key
    return serializer.dumps(email, salt="email-confirm-salt")


def send_confirmation_email(user_email):
    mail = configure_email()
    token = generate_confirmation_token(user_email)

    confirm_url = f"https://infolens.streamlit.app/?token={token}"

    msg = Message("Confirm Your Email Address", sender=st.secrets["email"]["username"], recipients=[user_email])
    msg.body = f"Hi! Please confirm your email address by clicking this link: {confirm_url}"

    with app.app_context():
        mail.send(msg)


def confirm_email(token):
    try:
        serializer = URLSafeTimedSerializer(st.secrets["app-secrets"]["secret_key"])
        email = serializer.loads(token, salt="email-confirm-salt", max_age=3600)
        db = connect_to_db()
        db["users"].update_one({"email": email}, {"$set": {"confirmed": True}})
        st.session_state.confirm_message = "Email confirmed! You may now log in."
    except SignatureExpired:
        st.error("The confirmation link has expired.")
    except BadSignature:
        st.error("Invalid confirmation link.")


def check_login():
    logged_in = cookies.get("logged_in")
    user_name = cookies.get("user_name")

    if logged_in == "True":
        st.session_state.logged_in = True
        st.session_state.user_name = user_name
    else:
        st.session_state.logged_in = False


def clear_login_session():
    st.session_state.logged_in = False
    st.session_state.user_name = ""
    st.session_state.confirm_message = ""  
    cookies["logged_in"] = "False"
    cookies["user_name"] = ""
    cookies.save()


def profile():
    st.title("Profile")

    if st.session_state.get("user_name"):
        st.write(f"Welcome, {st.session_state['user_name']}!")
        st.write("This is your profile management page, at the moment, all you can do here is delete your account, if you wish!")
    
    st.write("### Delete your account")
    st.warning("Deleting your account will permanently remove all of your data, including your prediction history.")

    confirmation_text = st.text_input("Type 'DELETE' to confirm", "")
    delete_button_disabled = confirmation_text != 'DELETE'
    delete_confirm_button = st.button("Delete Account", disabled=delete_button_disabled)

    if delete_confirm_button:
        if "email" in st.session_state: 
            db = connect_to_db()
            users_collection = db["users"]
            predictions_collection = db["predictions"]

            
            users_collection.delete_one({"email": st.session_state["email"]})

           
            predictions_collection.delete_many({"email": st.session_state["email"]})

            st.session_state.account_deleted_message = "Your account and prediction history have been deleted."
            clear_login_session()
            st.rerun()  
        else:
            st.error("Unable to delete account. No email found in session.")


def save_prediction(user_email, text, model, prediction):
    db = connect_to_db()
    predictions_collection = db["predictions"]
    timestamp = datetime.datetime.now()
    prediction_data = {
        "email": user_email,
        "text": text,
        "model": model,
        "timestamp": timestamp,
        "prediction": prediction
    }
    predictions_collection.insert_one(prediction_data)


def history():
    st.title("Your Prediction History")

    if "email" in st.session_state:
        db = connect_to_db()
        predictions_collection = db["predictions"]
        user_predictions = predictions_collection.find({"email": st.session_state["email"]})

       
        predictions_list = list(user_predictions)

        if len(predictions_list) == 0:
            st.write("You have no prediction history.")
        else:
            for prediction in predictions_list:
                st.write(f"**Text**: {prediction['text']}")
                st.write(f"**Model**: {prediction['model']}")
                st.write(f"**Timestamp**: {prediction['timestamp']}")
                outcome = "True" if prediction['prediction'] == 0 else "False"
                st.write(f"**Outcome**: {outcome}")
                st.write("---")
    else:
        st.error("Unable to fetch prediction history. No email found in session.")


def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "message" not in st.session_state:
        st.session_state["message"] = ""

    if "current_page" not in st.session_state:
        st.session_state.current_page = "Home"

   
    st.session_state.account_deleted_message = ""

    query_params = st.experimental_get_query_params()  
    if "token" in query_params and "token_processed" not in st.session_state:
        token = query_params["token"][0]
        confirm_email(token)
        st.session_state.token_processed = True  
        st.experimental_set_query_params()

    check_login()

    st.sidebar.title("Navigation")

    if st.sidebar.button("Home", key="home_button_sidebar"):
        st.session_state.current_page = "Home"

    if st.session_state.logged_in:
        if st.sidebar.button("Profile", key="profile_button_sidebar"):
            st.session_state.current_page = "Profile"
        if st.sidebar.button("Predict", key="predict_button_sidebar"):  
            st.session_state.current_page = "Predict"
        if st.sidebar.button("History", key="history_button_sidebar"):  
            st.session_state.current_page = "History"
        if st.sidebar.button("Log Out", key="logout_button_sidebar"):
            clear_login_session()
            st.session_state.current_page = "Home"
            st.session_state["message"] = "Logged out successfully!"
            st.rerun()
    else:
        if st.sidebar.button("Log In", key="login_button_sidebar"):
            st.session_state.current_page = "Log In"
        if st.sidebar.button("Sign Up", key="signup_button_sidebar"):
            st.session_state.current_page = "Sign Up"

    if st.session_state.current_page == "Home":
        home()
    elif st.session_state.current_page == "Predict" and st.session_state.logged_in:
        predict()
    elif st.session_state.current_page == "Profile" and st.session_state.logged_in:
        profile()
    elif st.session_state.current_page == "History" and st.session_state.logged_in:
        history()
    elif st.session_state.current_page == "Log In" and not st.session_state.logged_in:
        login()
    elif st.session_state.current_page == "Sign Up" and not st.session_state.logged_in:
        signup()


# Home page content
def home():
    st.title("Welcome to InfoLens!")

    if "account_deleted_message" in st.session_state and st.session_state.account_deleted_message:
        st.success(st.session_state.account_deleted_message)
        st.session_state.account_deleted_message = ""  

    if "confirm_message" in st.session_state and st.session_state.confirm_message:
        st.success(st.session_state.confirm_message)
        st.session_state.confirm_message = "" 

    st.write("InfoLens is a web-based application, designed to aid in the mitigation of disinformation found online.")
    st.write("At the moment, this application is under development and in somewhat of a pre-alpha stage, however \
             you are able to sign up securely, verify your email, make predictions on textual data and delete your \
             account if you so wish.")
    st.write("Use the navigation menu on the left to move about the app, happy predicting!")
    st_lottie(lottie_animation, height=300, key="disinformation_animation")
    st.write("**Techy Stuff**")
    st.write("For those of you who may be interested in the technical implementation of this application, the front-end is built \
             using Streamlit, there are various email validation and verification functions built in, with validation solved using \
             AbstractAPI, and verification links with tokens generated and sent automatically from my personal email address (for now).")
    st.write("Multiple machine learning classification models were build using scikit learn and tensorflow, with textual embeddings solved \
             using a pretrained DistilBERT model. These models, including an api, which anyone can post to, were then containerised and \
             deployed to GCP in a cloud run container (I highly reccommend this solution over AWS or other popular container services).")
    st.write("Finally MongoDB has been used to store and retrieve any user information, complete with password hashing and following \
             all the best practises, so don't worry your passwords are safe here! In addition to this, flask has been used in conjunction with streamlit to produce some hacky solutions to some problems \
             I've had to overcome building this application - anyone looking to build anything more complex than this should probably put\
             their faith in Django.")
    st.write("Thanks for checking out my application!")


# Prediction page
def predict():
    st.title("Make a Prediction")
    st.write("**Important:** although this application seeks to detect disinformation, building a generalised and accurate predictor \
             for this purpose without a collosal amount of data is a near impossible task for an indiviudal. This application is under \
             development and for all purpose and intents information classified here should not be heavily relied upon. Future iterations \
             of this application will be trained on larger corpuses of textual data and use more advanced classification methods, but for \
             now, this is merely a proof-of-concept application.")
    user_input = st.text_area("Enter text to analyze", placeholder="Type your text here...")
    
    model_options = ["cnn", "mlp", "xgb", "svm", "random_forest", "knn"]
    selected_model = st.selectbox("Select model", model_options, index=model_options.index("cnn"))

    if st.button("Classify", key="classify_button"):
        if user_input:
            result = make_prediction_via_api(user_input, selected_model)
            if result == 1:
                st.write("Response from our classification model indicates that this information is **FALSE**.")
            elif result == 0:
                st.write("Response from our classification model indicates that this information is **TRUE**.")
            
            save_prediction(st.session_state["email"], user_input, selected_model, result)
        else:
            st.warning("Please enter some text before clicking Classify.")



def signup():
    st.title("Sign Up")

    first_name = st.text_input("First Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Sign Up", key="signup_button"):
        # Perform email validation first
        if not validate_email_api(email):
            st.error("The email provided is invalid. Please provide a valid email address.")
            return  # Stop further execution if email is invalid
        else:
            # Email is valid, proceed with user creation and sending confirmation email
            db = connect_to_db()
            success, message = add_user(db, first_name, email, password)
            if success:
                send_confirmation_email(email)
                st.success("Confirmation email sent. Please check your inbox.")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error(message)



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
            st.session_state.user_name = user_name
            st.session_state.email = email 
            st.session_state.current_page = "Profile" 

            cookies["logged_in"] = "True"
            cookies["user_name"] = user_name
            cookies.save()

            st.rerun()
        else:
            st.error(user_name)

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
