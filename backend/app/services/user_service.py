import random
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.role import Role
from app.models.trust_score import TrustScore
from app.models.bank import BankAccount
from app.schemas.user import UserCreate
from app.security.password import hash_password

class UserService:
    @staticmethod
    def create_user(db: Session, user_in: UserCreate) -> User:
        # Check if user already exists
        existing_user = db.query(User).filter(
            (User.username == user_in.username) | (User.email == user_in.email)
        ).first()
        if existing_user:
            raise ValueError("Username or Email already registered")

        # Hash password
        hashed_pwd = hash_password(user_in.password)
        
        # Create User
        db_user = User(
            username=user_in.username,
            email=user_in.email,
            hashed_password=hashed_pwd,
            organization_id=user_in.organization_id
        )
        
        # Fetch and append the default USER role
        user_role = db.query(Role).filter(Role.name == "USER").first()
        if user_role:
            db_user.roles.append(user_role)
            
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        # Initialize Trust Score at 100
        trust_score = TrustScore(
            user_id=db_user.id,
            current_score=100,
            risk_level="LOW"
        )
        db.add(trust_score)

        # Provision Simulated Bank Account with balance $12,450.82
        acct_num = "".join([str(random.randint(0, 9)) for _ in range(10)])
        bank_acct = BankAccount(
            user_id=db_user.id,
            account_number=f"ACT-{acct_num}",
            balance=12450.82
        )
        db.add(bank_acct)
        
        db.commit()
        db.refresh(db_user)
        
        return db_user

    @staticmethod
    def get_by_id(db: Session, user_id: int) -> User | None:
        return db.query(User).filter(User.id == user_id).first()

    @staticmethod
    def get_by_username(db: Session, username: str) -> User | None:
        return db.query(User).filter(User.username == username).first()
