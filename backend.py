# backend.py
from pymongo import MongoClient
import bcrypt
import streamlit as st
import joblib
from transformers import DistilBertTokenizer, DistilBertModel
import torch

# Load the pre-trained model
@st.cache_resource
def load_model():
    return joblib.load('models/XGB.pkl')

model = load_model()

# Function to make predictions
def predict(text_embedding):
    return model.predict(text_embedding)

# Load the pre-trained DistilBERT model and tokenizer
tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
distilbert_model = DistilBertModel.from_pretrained('distilbert-base-uncased')

# Function to embed text using DistilBERT
def embed_text(text):
    inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=512)
    with torch.no_grad():
        outputs = distilbert_model(**inputs)
    return outputs.last_hidden_state.mean(dim=1)  # Embedding from the last hidden state

# Make predictions
def make_prediction(input_text):
    embedding = embed_text(input_text)  # Embed the input text
    prediction = predict(embedding.numpy())  # Make prediction using the loaded model
    return prediction


# Connect to MongoDB
def connect_to_db():
    username = st.secrets["mongo"]["username"]
    password = st.secrets["mongo"]["password"]
    cluster_url = st.secrets["mongo"]["cluster_url"]
    db_name = st.secrets["mongo"]["db_name"]

    # Create the connection string and connect to MongoDB
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
