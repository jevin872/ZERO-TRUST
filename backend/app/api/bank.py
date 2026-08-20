from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from typing import List

from app.database.connection import get_db
from app.models.user import User
from app.models.session import Session as UserSession
from app.models.bank import BankAccount, BankTransaction, BankBeneficiary
from app.schemas.bank import BankAccountResponse, BankTransactionResponse, TransferRequest, BeneficiaryCreate, BeneficiaryResponse
from app.security.permissions import get_current_user, get_current_session
from app.services.security_event_service import SecurityEventService
from app.scoring.trust_engine import TrustEngine

router = APIRouter(prefix="/bank", tags=["Simulated Banking"])

def check_banking_restrictions(user: User, db: Session):
    score_record = TrustEngine.get_or_create_trust_score(db, user.id)
    if score_record.risk_level in ["HIGH", "CRITICAL"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action blocked by ZeroTrustX Policy: {score_record.risk_level} Risk. Sensitive operations restricted."
        )

@router.get("/balance", response_model=BankAccountResponse)
def get_balance(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    acct = db.query(BankAccount).filter(BankAccount.user_id == current_user.id).first()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bank account not found."
        )
    return acct

@router.get("/transactions", response_model=List[BankTransactionResponse])
def get_transactions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    acct = db.query(BankAccount).filter(BankAccount.user_id == current_user.id).first()
    if not acct:
        return []
    return db.query(BankTransaction).filter(
        BankTransaction.account_id == acct.id
    ).order_by(BankTransaction.timestamp.desc()).all()

@router.post("/transfer", response_model=dict)
def simulate_transfer(
    request: Request,
    transfer_data: TransferRequest,
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    # 1. Enforce Zero Trust high-risk restrictions
    check_banking_restrictions(current_user, db)

    acct = db.query(BankAccount).filter(BankAccount.user_id == current_user.id).first()
    if not acct:
        raise HTTPException(status_code=404, detail="Bank account not found.")

    if acct.balance < transfer_data.amount:
        raise HTTPException(status_code=400, detail="Insufficient simulated funds.")

    # Execute transfer
    acct.balance -= transfer_data.amount
    tx = BankTransaction(
        account_id=acct.id,
        transaction_type="TRANSFER_OUT",
        amount=transfer_data.amount,
        description=f"Simulated Transfer to Acct {transfer_data.beneficiary_account_number}: {transfer_data.description}"
    )
    db.add(tx)
    db.commit()

    # Log security event
    ip_address = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "unknown")
    
    event_type = "TRANSACTION_ATTEMPT"
    if transfer_data.amount >= 5000:
        event_type = "LARGE_TRANSACTION"
        
    SecurityEventService.log_event(
        db=db,
        user_id=current_user.id,
        event_type=event_type,
        ip_address=ip_address,
        device_info=user_agent[:255],
        session_id=current_session.id
    )

    return {
        "success": True,
        "message": f"Simulated transfer of ${transfer_data.amount:.2f} executed successfully.",
        "new_balance": acct.balance
    }

@router.get("/beneficiaries", response_model=List[BeneficiaryResponse])
def get_beneficiaries(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(BankBeneficiary).filter(BankBeneficiary.user_id == current_user.id).all()

@router.post("/beneficiaries", response_model=BeneficiaryResponse)
def add_beneficiary(
    request: Request,
    beneficiary_data: BeneficiaryCreate,
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    # Enforce Zero Trust restrictions
    check_banking_restrictions(current_user, db)

    new_beneficiary = BankBeneficiary(
        user_id=current_user.id,
        name=beneficiary_data.name,
        account_number=beneficiary_data.account_number,
        bank_name=beneficiary_data.bank_name
    )
    db.add(new_beneficiary)
    db.commit()
    db.refresh(new_beneficiary)

    # Log security event
    ip_address = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "unknown")
    
    SecurityEventService.log_event(
        db=db,
        user_id=current_user.id,
        event_type="BENEFICIARY_ADDED",
        ip_address=ip_address,
        device_info=user_agent[:255],
        session_id=current_session.id
    )

    return new_beneficiary
