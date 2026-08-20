from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class BankAccountResponse(BaseModel):
    account_number: str
    balance: float

    class Config:
        from_attributes = True

class BankTransactionResponse(BaseModel):
    id: int
    transaction_type: str
    amount: float
    description: str
    timestamp: datetime

    class Config:
        from_attributes = True

class TransferRequest(BaseModel):
    amount: float
    description: str
    beneficiary_account_number: str

class BeneficiaryCreate(BaseModel):
    name: str
    account_number: str
    bank_name: Optional[str] = "ZeroTrust Demo Bank"

class BeneficiaryResponse(BaseModel):
    id: int
    name: str
    account_number: str
    bank_name: str

    class Config:
        from_attributes = True
