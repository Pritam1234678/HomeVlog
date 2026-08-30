from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class SignupRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class VlogCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    content: str = Field(..., min_length=10)


class VlogUpdate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    content: str = Field(..., min_length=10)


class AuthorResponse(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True


class VlogResponse(BaseModel):
    id: int
    title: str
    content: str
    author: AuthorResponse
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
