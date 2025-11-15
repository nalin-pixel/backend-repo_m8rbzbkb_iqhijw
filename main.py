import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Turf as TurfSchema, Booking as BookingSchema

# ----------------------------------------------------------------------------
# App & Security Config
# ----------------------------------------------------------------------------
app = FastAPI(title="PlayHub API", description="Turf booking platform backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# ----------------------------------------------------------------------------
# Helpers & Models
# ----------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    avatar_url: Optional[str] = None

class RegisterPayload(BaseModel):
    name: str
    email: EmailStr
    password: str

class CreateTurfPayload(BaseModel):
    name: str
    location: str
    description: Optional[str] = None
    price_per_hour: float
    images: List[str] = []
    facilities: List[str] = []

class CreateBookingPayload(BaseModel):
    turf_id: str
    date: str
    start_time: str
    end_time: str
    notes: Optional[str] = None


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_email(email: str):
    users = get_documents("user", {"email": email})
    return users[0] if users else None


def get_user_by_id(user_id: str):
    try:
        return db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user


def require_admin(user):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


# ----------------------------------------------------------------------------
# Root & Health
# ----------------------------------------------------------------------------
@app.get("/")
def read_root():
    return {"message": "PlayHub Backend Running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------
@app.post("/auth/register", response_model=UserOut)
def register(payload: RegisterPayload):
    existing = get_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = UserSchema(
        name=payload.name,
        email=payload.email,
        password_hash=get_password_hash(payload.password),
        role="user",
        avatar_url=None,
        is_active=True,
    )
    inserted_id = create_document("user", user)
    return UserOut(
        id=str(inserted_id),
        name=user.name,
        email=user.email,
        role=user.role,
        avatar_url=user.avatar_url,
    )


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.get("is_active", True):
        raise HTTPException(status_code=400, detail="User is inactive")

    access_token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=access_token)


@app.get("/auth/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    return UserOut(
        id=str(current_user["_id"]),
        name=current_user.get("name"),
        email=current_user.get("email"),
        role=current_user.get("role", "user"),
        avatar_url=current_user.get("avatar_url"),
    )


# ----------------------------------------------------------------------------
# Turf Endpoints
# ----------------------------------------------------------------------------
@app.get("/turfs")
def list_turfs():
    items = list(db["turf"].find({"is_active": True}))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.post("/turfs")
def create_turf(payload: CreateTurfPayload, current_user=Depends(get_current_user)):
    require_admin(current_user)
    turf = TurfSchema(
        name=payload.name,
        location=payload.location,
        description=payload.description,
        price_per_hour=payload.price_per_hour,
        images=payload.images,
        facilities=payload.facilities,
        is_active=True,
    )
    inserted_id = create_document("turf", turf)
    return {"id": str(inserted_id)}


@app.get("/turfs/{turf_id}")
def get_turf(turf_id: str):
    try:
        doc = db["turf"].find_one({"_id": ObjectId(turf_id)})
        if not doc:
            raise HTTPException(status_code=404, detail="Turf not found")
        doc["id"] = str(doc.pop("_id"))
        return doc
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid turf id")


# ----------------------------------------------------------------------------
# Booking Endpoints
# ----------------------------------------------------------------------------
@app.post("/bookings")
def create_booking(payload: CreateBookingPayload, current_user=Depends(get_current_user)):
    # Basic clash check: same turf + date with overlapping times
    existing = list(db["booking"].find({
        "turf_id": payload.turf_id,
        "date": payload.date,
        "status": {"$ne": "cancelled"}
    }))
    def overlaps(a_start, a_end, b_start, b_end):
        return not (a_end <= b_start or b_end <= a_start)

    for b in existing:
        if overlaps(payload.start_time, payload.end_time, b.get("start_time"), b.get("end_time")):
            raise HTTPException(status_code=400, detail="Time slot not available")

    turf = db["turf"].find_one({"_id": ObjectId(payload.turf_id)})
    if not turf:
        raise HTTPException(status_code=404, detail="Turf not found")

    # Compute price by hour difference (simplified)
    try:
        sh, sm = map(int, payload.start_time.split(":"))
        eh, em = map(int, payload.end_time.split(":"))
        hours = max(0.5, ((eh + em/60) - (sh + sm/60)))
    except Exception:
        hours = 1.0

    total = float(turf.get("price_per_hour", 0)) * hours

    booking = BookingSchema(
        user_id=str(current_user["_id"]),
        turf_id=payload.turf_id,
        date=payload.date,
        start_time=payload.start_time,
        end_time=payload.end_time,
        total_price=round(total, 2),
        status="confirmed",
        notes=payload.notes,
    )
    inserted_id = create_document("booking", booking)
    return {"id": str(inserted_id), "total_price": round(total, 2)}


@app.get("/bookings/me")
def my_bookings(current_user=Depends(get_current_user)):
    items = list(db["booking"].find({"user_id": str(current_user["_id"]) }))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# ----------------------------------------------------------------------------
# Admin Dashboard
# ----------------------------------------------------------------------------
@app.get("/admin/summary")
def admin_summary(current_user=Depends(get_current_user)):
    require_admin(current_user)
    total_users = db["user"].count_documents({})
    total_turfs = db["turf"].count_documents({})
    total_bookings = db["booking"].count_documents({})

    recent_bookings = list(db["booking"].find({}).sort("_id", -1).limit(5))
    for it in recent_bookings:
        it["id"] = str(it.pop("_id"))

    return {
        "users": total_users,
        "turfs": total_turfs,
        "bookings": total_bookings,
        "recent_bookings": recent_bookings,
    }


# ----------------------------------------------------------------------------
# Schema exposure for DB viewer
# ----------------------------------------------------------------------------
@app.get("/schema")
def get_schema():
    return {
        "user": UserSchema.model_json_schema(),
        "turf": TurfSchema.model_json_schema(),
        "booking": BookingSchema.model_json_schema(),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
