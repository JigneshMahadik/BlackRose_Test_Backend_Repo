from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
from pymongo import MongoClient

# Authentication
import bcrypt
import jwt
from fastapi.security import OAuth2PasswordBearer
import base64

import random
import asyncio
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import json
import logging

# File Modification Libraries
import pandas as pd
from filelock import FileLock
import os


logging.basicConfig(level=logging.INFO)


# MongoDB Setup
client = MongoClient("mongodb+srv://jignesh:dUaszhl26B0rpW0f@cluster0.s7hzif4.mongodb.net/")
db = client['user_db']
users_collection = db['users']
random_numbers_collection = db['random_numbers']

# FastAPI instance
app = FastAPI()

# Path to the CSV file and its lock
CSV_FILE = "data.csv"
LOCK_FILE = "data.lock"

# Ensure CSV exists
if not os.path.exists(CSV_FILE):
    df = pd.DataFrame(columns=["user", "broker", "api_key", "api_secret", "pnl", "margin", "max_risk"])
    df.to_csv(CSV_FILE, index=False)

# JWT Secret Key
SECRET_KEY = "APISECRET_77485"

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://black-rose-frontend.vercel.app"],  # Replace with your frontend's URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Pydantic Models
class RegisterModel(BaseModel):
    username: str
    password: str

class LoginModel(BaseModel):
    username: str
    password: str

class UpdateModel(BaseModel):
    user: str
    field: str
    value: str

# Helper Function to Generate JWT Token
def create_jwt_token(username: str):
    expiration = datetime.utcnow() + timedelta(hours=1)
    payload = {"username": username, "exp": expiration}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

# Helper Function to Validate JWT Token
def validate_jwt_token(token: str):
    try:
        decoded_token = jwt.decode(token, "<your-secret-key>", algorithms=["HS256"])
        return decoded_token
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token.")

# Registration API
@app.post("/register")
async def register(user: RegisterModel):
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(10))
    encoded_password = base64.b64encode(hashed_password)
    users_collection.insert_one({"username": user.username, "password": encoded_password})
    return {"message": "User registered successfully"}

# Login API
@app.post("/login")
async def login(user: LoginModel):
    user_data = users_collection.find_one({"username": user.username})
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    stored_hashed_password = base64.b64decode(user_data['password'])
    if not bcrypt.checkpw(user.password.encode('utf-8'), stored_hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_jwt_token(user.username)
    return {"token": token}

# WebSocket API for Random Number Generation
@app.websocket("/ws/random")
async def websocket_random_number(websocket: WebSocket):
    print("Client attempting to connect.")
    await websocket.accept()
    print("Connection accepted.")
    
    try:
        # Wait to receive a token message
        token_message = await websocket.receive_text()
        logging.info(f"Received WebSocket message: {token_message}")

        # Handle empty message
        if not token_message.strip():
            await websocket.send_json({"error": "Token message is empty."})
            await websocket.close()
            return

        # Handle invalid JSON
        try:
            token_data = json.loads(token_message)
            logging.info(f"Parsed token data: {token_data}")
        except json.JSONDecodeError:
            await websocket.send_json({"error": "Invalid JSON format."})
            await websocket.close()
            return

        # Validate token existence
        token = token_data.get("token")
        logging.info(f"Extracted token: {token}")
        if not token:
            await websocket.send_json({"error": "Token is missing in the message."})
            await websocket.close()
            return

        # Validate the token
        try:
            validate_jwt_token(token)
        except ValueError as e:
            await websocket.send_json({"error": str(e)})
            await websocket.close()
            return

        # Send random numbers
        while True:
            random_number = random.randint(1, 100)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            random_numbers_collection.insert_one({"random_number": random_number, "timestamp": timestamp})
            logging.info(f"Sent random number: {random_number}, Timestamp: {timestamp}")
            await websocket.send_json({"random_number": random_number, "timestamp": timestamp})
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        logging.info("Client disconnected.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        await websocket.close()

# Fetch Stored Random Numbers
@app.get("/random-numbers")
def get_random_numbers():
    random_numbers = list(random_numbers_collection.find({}, {"_id": 0}))
    return random_numbers

# Fetch all records stored in CSV file
@app.get("/data")
def get_all_data():
    with FileLock(LOCK_FILE):
        df = pd.read_csv(CSV_FILE)
        return df.to_dict(orient="records")

# Update a Particular Record
@app.put("/data")
def update_data(update: UpdateModel):
    with FileLock(LOCK_FILE):
        df = pd.read_csv(CSV_FILE)
        if update.user not in df["user"].values:
            raise HTTPException(status_code=404, detail="User not found")
        if update.field not in df.columns:
            raise HTTPException(status_code=400, detail=f"Field '{update.field}' does not exist")
        df.loc[df["user"] == update.user, update.field] = update.value
        df.to_csv(CSV_FILE, index=False)
        return {"message": f"Field '{update.field}' updated successfully for user '{update.user}'"}

# Add new record to CSV file
@app.post("/data")
def add_record(record: dict):
    with FileLock(LOCK_FILE):
        df = pd.read_csv(CSV_FILE)
        new_row = pd.DataFrame([record])
        df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv(CSV_FILE, index=False)
        return {"message": "Record added successfully"}

# Delete a particular record
@app.delete("/data/{user}")
def delete_record(user: str):
    with FileLock(LOCK_FILE):
        df = pd.read_csv(CSV_FILE)
        if user not in df["user"].values:
            return {"error": f"User '{user}' not found."}
        df = df[df["user"] != user]
        df.to_csv(CSV_FILE, index=False)
    return {"message": f"Record for user '{user}' deleted successfully."}

# Default root path
@app.get("/")
def read_root():
    return {"message": "Welcome to my FastAPI application!"}

@app.head("/", include_in_schema=False)
async def read_root_head():
    return {"message": "OK"}  # Response body won't be included in a HEAD request
