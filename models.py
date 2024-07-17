import atexit
import datetime
from typing import List

from config import (
    POSTGRES_DB,
    POSTGRES_HOST,
    POSTGRES_PASSWORD,
    POSTGRES_PORT,
    POSTGRES_USER,
)
from sqlalchemy import create_engine, String, ForeignKey, DateTime, Text, func
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column, relationship

engine = create_engine(
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}",
)
Session = sessionmaker(bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'adv_user'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(
        String(50), unique=True, index=True, nullable=False
    )
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(100))
    advertisements: Mapped[List['Advertisement']] = relationship(back_populates="owner")

    @property
    def json(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email
        }


class Advertisement(Base):
    __tablename__ = 'advertisement'

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    description: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    owner_id: Mapped[int] = mapped_column(ForeignKey('adv_user.id'))
    owner: Mapped[User] = relationship(User, back_populates="advertisements")

    @property
    def json(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'created_at': self.created_at,
            'owner': self.owner.name
        }


Base.metadata.create_all(bind=engine)

atexit.register(engine.dispose)
