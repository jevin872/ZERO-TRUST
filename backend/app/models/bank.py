from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.database.connection import Base

class BankAccount(Base):
    __tablename__ = "bank_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    account_number = Column(String(20), unique=True, nullable=False)
    balance = Column(Float, default=12450.82, nullable=False)

    # Relationships
    user = relationship("User")
    transactions = relationship("BankTransaction", back_populates="account", cascade="all, delete-orphan")

class BankTransaction(Base):
    __tablename__ = "bank_transactions"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("bank_accounts.id", ondelete="CASCADE"), nullable=False)
    transaction_type = Column(String(20), nullable=False) # TRANSFER_OUT, TRANSFER_IN, DEPOSIT
    amount = Column(Float, nullable=False)
    description = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)

    # Relationships
    account = relationship("BankAccount", back_populates="transactions")

class BankBeneficiary(Base):
    __tablename__ = "bank_beneficiaries"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    account_number = Column(String(20), nullable=False)
    bank_name = Column(String(100), default="ZeroTrust Demo Bank", nullable=False)

    # Relationships
    user = relationship("User")
