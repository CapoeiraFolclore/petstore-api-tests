"""PetStore API models derived from swagger definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional

PetStatus = Literal["available", "pending", "sold"]
OrderStatus = Literal["placed", "approved", "delivered"]


@dataclass
class Category:
    id: Optional[int] = None
    name: Optional[str] = None


@dataclass
class Tag:
    id: Optional[int] = None
    name: Optional[str] = None


@dataclass
class Pet:
    name: str
    photo_urls: List[str]
    id: Optional[int] = None
    category: Optional[Category] = None
    tags: List[Tag] = field(default_factory=list)
    status: Optional[PetStatus] = None

    def to_json(self) -> dict:
        payload = {
            "name": self.name,
            "photoUrls": self.photo_urls,
        }
        if self.id is not None:
            payload["id"] = self.id
        if self.category is not None:
            payload["category"] = {"id": self.category.id, "name": self.category.name}
        if self.tags:
            payload["tags"] = [{"id": tag.id, "name": tag.name} for tag in self.tags]
        if self.status is not None:
            payload["status"] = self.status
        return payload


@dataclass
class Order:
    id: Optional[int] = None
    pet_id: Optional[int] = None
    quantity: Optional[int] = None
    ship_date: Optional[str] = None
    status: Optional[OrderStatus] = None
    complete: Optional[bool] = None

    def to_json(self) -> dict:
        payload = {}
        if self.id is not None:
            payload["id"] = self.id
        if self.pet_id is not None:
            payload["petId"] = self.pet_id
        if self.quantity is not None:
            payload["quantity"] = self.quantity
        if self.ship_date is not None:
            payload["shipDate"] = self.ship_date
        if self.status is not None:
            payload["status"] = self.status
        if self.complete is not None:
            payload["complete"] = self.complete
        return payload


@dataclass
class User:
    id: Optional[int] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    phone: Optional[str] = None
    user_status: Optional[int] = None

    def to_json(self) -> dict:
        payload = {}
        if self.id is not None:
            payload["id"] = self.id
        if self.username is not None:
            payload["username"] = self.username
        if self.first_name is not None:
            payload["firstName"] = self.first_name
        if self.last_name is not None:
            payload["lastName"] = self.last_name
        if self.email is not None:
            payload["email"] = self.email
        if self.password is not None:
            payload["password"] = self.password
        if self.phone is not None:
            payload["phone"] = self.phone
        if self.user_status is not None:
            payload["userStatus"] = self.user_status
        return payload


@dataclass
class ApiResponse:
    code: Optional[int] = None
    type: Optional[str] = None
    message: Optional[str] = None
