**## Core Features**

### **Authentication**
- Basic authentication implementation.
- Accepts any username and password.
- Issues session tokens (JWT or UUID-based).
- Validates session tokens for protected endpoints.

### **Random Number Generator**
- Generates random numbers every second.
- Stores numbers in the database (MongoDB) as key-value pairs:
  - **Key:** Current timestamp.
  - **Value:** Random number.

### **API Endpoints**
1. **Login Endpoint**:
   - Issues tokens for authentication.

2. **Real-Time Data Streaming**:
   - Provides a WebSocket or REST endpoint to stream random numbers (requires authentication).

3. **CSV File Fetch**:
   - Fetches the provided `backend_table.csv` (requires authentication).

4. **CRUD Operations**:
   - Allows users to perform Create, Read, Update, and Delete (CRUD) operations on `backend_table.csv`.
   - Changes persist to the file.
   - Returns errors for invalid operations.

### **Concurrency Management**
- Implements a file locking mechanism to handle simultaneous CRUD operations by multiple users.

---

**## Database**
- Stores:
  - Login user data validates with user existence in mongoDB database.
  - Generated random numbers (timestamp and value) and stores it in mongoDB database.

---

**## Hosting**
- Deployed on free platforms such as Render.

---

**## Installation Instructions**

### **Local Setup**
1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```
2. Navigate to the project directory:
   ```bash
   cd backend
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the FastAPI server:
   ```bash
   uvicorn main:app --reload
   ```
   
---

**## Testing Instructions**
1. **Login**:
   - Test authentication by providing a username and password.

2. **WebSocket**:
   - Connect to the WebSocket endpoint and validate real-time data streaming.

3. **CRUD Operations**:
   - Test Create, Read, Update, and Delete functionalities on `backend_table.csv`.

4. **CSV Fetch**:
   - Fetch and verify the contents of `backend_table.csv`.

5. **Concurrency**:
   - Simulate multiple users performing CRUD operations simultaneously.

---
