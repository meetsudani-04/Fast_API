from hashlib import scrypt
import os
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from database import Base, SessionLocal, engine
import models
from database import get_db
from auth import hash_password, verify_password
import requests 
import secrets
import random
import string
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from jose import jwt
from dotenv import load_dotenv


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Jinja2 templates
templates = Jinja2Templates(directory="templates")

load_dotenv()
# google signup
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
# email
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") 

Base.metadata.create_all(bind=engine)
db = SessionLocal()

# send otp email
def send_otp_email(to_email: str, otp: str):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    msg['Subject'] = "Password Reset OTP"
    
    body = f"Your OTP for password reset is: {otp}\nThis code is valid for 1 minutes."
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")
    
# Google OAuth2 endpoints ------------------------------------------------------------------------------------------------
@app.get("/login/google/")
async def login_google():
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"response_type=code&client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={GOOGLE_REDIRECT_URI}&"
        f"scope=openid%20profile%20email&access_type=offline"
    )
    return RedirectResponse(url=google_auth_url)

@app.get("/auth/google/")
async def auth_google(code: str, db: Session = Depends(get_db)):
    token_url = "https://accounts.google.com/o/oauth2/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    response = requests.post(token_url, data=data)
    access_token = response.json().get("access_token")
    user_info = requests.get("https://www.googleapis.com/oauth2/v1/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    user_data = user_info.json()

    email = user_data.get("email")
    existing_user = db.query(models.User).filter(models.User.email == email).first()
    if not existing_user:
        base_username = user_data.get("name", email.split("@")[0]).replace(" ", "_")
        username = base_username
        suffix = 1
        while db.query(models.User).filter(models.User.username == username).first():
            username = f"{base_username}_{suffix}"
            suffix += 1
        user = models.User(
            username=username,
            email=email,
            hashed_password=None
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    return RedirectResponse(url="/", status_code=302)

@app.get("/token")
async def get_token(token: str = Depends(oauth2_scheme)):
    try:
        return jwt.decode(token, GOOGLE_CLIENT_SECRET, algorithms=["HS256"])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
#  Display Data --------------------------------------------------------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
        }
    )

# signup page --------------------------------------------------------------------------------------------------------------------------
@app.get("/signup", response_class=HTMLResponse)
async def get_signup(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/signup", response_class=HTMLResponse)
async def post_signup(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),

    db: Session = Depends(get_db)
):
    existing_user = db.query(models.User).filter(models.User.email == email).first()
    if existing_user:
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Email already registered"})

    hashed_password = hash_password(password)
    user = models.User(username=username, email=email, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return RedirectResponse(url="/login", status_code=302)

# login page --------------------------------------------------------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def get_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def post_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

    response = RedirectResponse(url="/", status_code=302)
    return response

# forgot password page --------------------------------------------------------------------------------------------------------------------------
@app.get("/forgot-password", response_class=HTMLResponse)
async def get_forgot_password(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot-password", response_class=HTMLResponse)
async def post_forgot_password(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse(
            "forgot_password.html",
            {"request": request, "error": "No account found with that email"}
        )

    otp = ''.join(random.choices(string.digits, k=6))
    otp_expiry = datetime.now() + timedelta(minutes=2)

    # OTP record
    otp_record = models.OTP(user_id=user.id, otp=otp, otp_expiry=otp_expiry)
    db.add(otp_record)
    db.commit()

    # Send OTP
    send_otp_email(user.email, otp)

    return RedirectResponse(url=f"/verify-otp?email={email}", status_code=302)

# verify otp page --------------------------------------------------------------------------------------------------------------------------
@app.get("/verify-otp", response_class=HTMLResponse)
async def get_verify_otp(request: Request,email: str):
    return templates.TemplateResponse("verify_otp.html", {"request": request,"email":email})

@app.post("/verify-otp", response_class=HTMLResponse)
async def post_verify_otp(
    request: Request,
    email: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse(
            "verify_otp.html",
            {"request": request, "email": email, "error": "No account found with that email"}
        )

    otp_record = db.query(models.OTP).filter(
        models.OTP.user_id == user.id,
        models.OTP.otp == otp,
        models.OTP.otp_expiry > datetime.now(),
        
    ).first()

    if not otp_record:
        return templates.TemplateResponse(
            "verify_otp.html",
            {"request": request, "email": email, "error": "Invalid or expired OTP"}
        )

    db.delete(otp_record)
    db.commit()

    return RedirectResponse(url=f"/reset-password?email={email}", status_code=302)

# reset password page --------------------------------------------------------------------------------------------------------------------------
@app.get("/reset-password", response_class=HTMLResponse)
async def get_reset_password(request: Request ,email: str):
    return templates.TemplateResponse("reset_password.html", {"request": request, "email":email})

@app.post("/reset-password", response_class=HTMLResponse)
async def post_reset_password(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "email": email, "error": "No account found with that email"}
        )

    # Update password
    user.hashed_password = hash_password(password)
    db.commit()

    # Invalidate all OTPs for this user
    db.query(models.OTP).filter(models.OTP.user_id == user.id).delete()
    db.commit()

    return RedirectResponse(url="/login", status_code=302)
