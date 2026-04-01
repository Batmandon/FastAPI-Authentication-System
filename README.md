# FastAPI Authentication System

A secure authentication backend built with FastAPI.
This project implements user registration, login, password hashing, and token-based authentication.


## Features

* User registration
* Secure password hashing
* Login authentication
* JWT token generation
* Protected routes
* SQLite database integration

## Tech Stack

Backend

* Python
* FastAPI

Security

* JWT Authentication
* Password Hashing (bcrypt / passlib)

Database

* SQLite


## Project Structure

```
app/
 ├ main.py
 ├ database.py
 ├ models.py
 ├ schemas.py
 ├ auth.py
 ├ routes/
 │    ├ login.py
 │    └ register.py
```

## Installation

Clone the repository

```
git clone https://github.com/Batmandon/fastapi-auth-system.git
cd fastapi-auth-system
```

Create virtual environment

```
python -m venv venv
```

Activate environment

Windows

```
venv\Scripts\activate
```

Install dependencies

```
pip install -r requirements.txt
```

Run the server

```
uvicorn main:app --reload
```

---

## API Endpoints

Register user

```
POST /register
```

Login user

```
POST /login
```

Protected route example

```
GET /profile
```

---

## Future Improvements

* PostgreSQL database support
* Refresh token system
* OAuth authentication
* Role-based access control

---

## Author

Batman
