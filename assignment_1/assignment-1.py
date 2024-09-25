# main.py
from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import pyotp
import qrcode
import base64
from io import BytesIO

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
users_db = {}

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.mfa_enabled = False
        self.mfa_secret = None

@app.post("/register/")
async def register(username: str = Form(...), password: str = Form(...)):
    if username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    users_db[username] = User(username=username, password=password)
    return {"message": "User registered successfully"}

@app.post("/login/")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form.username)
    if user and user.password == form.password:
        if user.mfa_enabled:
            raise HTTPException(status_code=401, detail="MFA required. Please verify your OTP.")
        return {"message": "Login successful", "access_token": "your_access_token_here"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/activate_mfa/")
async def activate_mfa(username: str = Form(...)):
    user = users_db.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.mfa_secret = pyotp.random_base32()
    user.mfa_enabled = True

    uri = f"otpauth://totp/{username}?secret={user.mfa_secret}&issuer=MyApp"
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    img_str = base64.b64encode(buf.getvalue()).decode()

    return HTMLResponse(content=f"<h1>Scan this QR Code</h1><img src='data:image/png;base64,{img_str}'/>")

@app.post("/verify_mfa/")
async def verify_mfa(username: str = Form(...), otp: str = Form(...)):
    user = users_db.get(username)
    if not user or not user.mfa_enabled:
        raise HTTPException(status_code=404, detail="User not found or MFA not enabled")

    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(otp):
        return {"message": "MFA verified. You can now log in."}
    raise HTTPException(status_code=400, detail="Invalid OTP")

@app.post("/final_login/")
async def final_login(username: str = Form(...), otp: str = Form(...)):
    user = users_db.get(username)
    if user and user.mfa_enabled:
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(otp):
            return {"message": "Login successful", "access_token": "your_access_token_here"}
        raise HTTPException(status_code=400, detail="Invalid OTP")
    raise HTTPException(status_code=401, detail="Invalid credentials or MFA not enabled")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
