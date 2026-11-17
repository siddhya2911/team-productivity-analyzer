from pydantic import BaseModel, EmailStr, Field
from app.models.user import UserRole

class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool
    model_config = {"from_attributes": True}

class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    # Only admins can set a non-employee role; enforced server-side
    role: UserRole = UserRole.employee

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut

class RefreshIn(BaseModel):
    refresh_token: str