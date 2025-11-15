"""
Database Schemas for PlayHub (Turf Booking)

Each Pydantic model represents a MongoDB collection. Collection name = lowercase class name.

- User -> user
- Turf -> turf
- Booking -> booking
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt hashed password")
    role: str = Field("user", description="user | admin")
    avatar_url: Optional[str] = Field(None, description="Profile avatar URL")
    is_active: bool = Field(True, description="Whether user is active")

class Turf(BaseModel):
    name: str = Field(..., description="Turf name")
    location: str = Field(..., description="City/Area")
    description: Optional[str] = Field(None, description="Short description")
    price_per_hour: float = Field(..., ge=0, description="Hourly price")
    images: List[str] = Field(default_factory=list, description="Image URLs")
    facilities: List[str] = Field(default_factory=list, description="List of facilities")
    is_active: bool = Field(True, description="Visible to users")

class Booking(BaseModel):
    user_id: str = Field(..., description="User ObjectId as string")
    turf_id: str = Field(..., description="Turf ObjectId as string")
    date: str = Field(..., description="ISO date (YYYY-MM-DD)")
    start_time: str = Field(..., description="Start time (HH:MM)")
    end_time: str = Field(..., description="End time (HH:MM)")
    total_price: float = Field(..., ge=0, description="Computed total price")
    status: str = Field("confirmed", description="confirmed | cancelled | pending")
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
