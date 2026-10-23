from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import func, inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import settings
from .database import Base, SessionLocal, engine, get_db
from .models import (
    Attendance, AttendanceStatus, Employee, EmployeeStatus, Leave, LeaveBalance, LeavePolicy, LeaveStatus,
    LeaveType, Notification, Payroll, Role, User,
)
from .schemas import (
    AdminUserCreate, AdminUserUpdate, AttendanceMark, AttendanceOut, EmployeeCreate, EmployeeOut, EmployeeUpdate,
    LeaveBalanceOut, LeaveCreate, LeaveOut, LeavePolicyCreate, LeavePolicyOut, LeavePolicyUpdate, LeaveReview,
    NotificationOut, PayrollCreate, PayrollOut, RegisterInput, TokenOut, UserOut,
)
from .security import create_access_token, hash_password, verify_password

Base.metadata.create_all(bind=engine)


def migrate_existing_schema() -> None:
    migrations = {
        "users": {"is_active": "BOOLEAN NOT NULL DEFAULT 1"},
        "attendance": {"is_late": "BOOLEAN NOT NULL DEFAULT 0"},
        "payroll": {"allowances": "FLOAT NOT NULL DEFAULT 0"},
    }
    with engine.begin() as connection:
        for table, columns in migrations.items():
            existing = {column["name"] for column in inspect(connection).get_columns(table)}
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))


migrate_existing_schema()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap_admin()
    yield


app = FastAPI(
    title="WorkSphere HRMS",
    version="1.0.0",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Health", "description": "Service status"},
        {"name": "Auth", "description": "Registration, sign-in, and user accounts"},
        {"name": "Employees", "description": "Employee profiles and directory"},
        {"name": "Attendance", "description": "Check-in, check-out, and attendance records"},
        {"name": "Leaves", "description": "Leave requests and approvals"},
        {"name": "Payroll", "description": "Payroll records and payslips"},
        {"name": "Notifications", "description": "Personal notifications"},
        {"name": "Dashboard", "description": "HR and administrator analytics"},
    ],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.frontend_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired access token", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        user_id = int(payload["sub"])
        token_role = Role(payload["role"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise unauthorized
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.role != token_role:
        raise unauthorized
    return user


def require_roles(*roles: Role):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="You do not have permission to perform this action")
        return user
    return dependency


def get_employee(db: Session, user: User) -> Employee:
    employee = db.scalar(select(Employee).where(Employee.user_id == user.id))
    if employee is None:
        raise HTTPException(status_code=404, detail="Employee profile not found")
    return employee


def employee_out(employee: Employee) -> dict:
    return {
        "id": employee.id, "user_id": employee.user_id, "full_name": employee.full_name,
        "designation": employee.designation, "department": employee.department,
        "joining_date": employee.joining_date, "salary": employee.salary, "status": employee.status,
        "username": employee.user.username, "email": employee.user.email,
    }


def attendance_out(row: Attendance) -> dict:
    hours = 0.0
    if row.check_in and row.check_out:
        start = row.check_in.replace(tzinfo=timezone.utc) if row.check_in.tzinfo is None else row.check_in
        end = row.check_out.replace(tzinfo=timezone.utc) if row.check_out.tzinfo is None else row.check_out
        hours = round(max(0, (end - start).total_seconds()) / 3600, 2)
    return {"id": row.id, "employee_id": row.employee_id, "check_in": row.check_in, "check_out": row.check_out,
            "date": row.date, "status": row.status, "is_late": row.is_late,
            "working_hours": hours, "employee_name": row.employee.full_name}


def leave_out(row: Leave) -> dict:
    return {"id": row.id, "employee_id": row.employee_id, "leave_type": row.leave_type,
            "start_date": row.start_date, "end_date": row.end_date, "reason": row.reason,
            "status": row.status, "created_at": row.created_at, "employee_name": row.employee.full_name}


def payroll_out(row: Payroll) -> dict:
    return {"id": row.id, "employee_id": row.employee_id, "basic_salary": row.basic_salary,
            "allowances": row.allowances, "deductions": row.deductions, "bonus": row.bonus, "net_salary": row.net_salary,
            "month": row.month, "created_at": row.created_at, "employee_name": row.employee.full_name}


def leave_days(start_date: date, end_date: date) -> int:
    return (end_date - start_date).days + 1


def ensure_leave_balances(db: Session, employee_id: int) -> None:
    policies = db.scalars(select(LeavePolicy)).all()
    balances = {
        balance.leave_type
        for balance in db.scalars(select(LeaveBalance).where(LeaveBalance.employee_id == employee_id)).all()
    }
    for policy in policies:
        if policy.leave_type not in balances:
            db.add(LeaveBalance(employee_id=employee_id, leave_type=policy.leave_type,
                                remaining_days=policy.total_days_allowed))
    db.flush()


def ensure_default_leave_policies(db: Session) -> None:
    defaults = {LeaveType.SICK: 10, LeaveType.CASUAL: 10, LeaveType.PAID: 15}
    for leave_type, days in defaults.items():
        if db.scalar(select(LeavePolicy).where(LeavePolicy.leave_type == leave_type)) is None:
            db.add(LeavePolicy(leave_type=leave_type, total_days_allowed=days))
    db.flush()


def notify(db: Session, user_id: int, title: str, message: str) -> None:
    db.add(Notification(user_id=user_id, title=title, message=message))


def bootstrap_admin() -> None:
    with SessionLocal() as db:
        exists = db.scalar(select(User).where(User.role == Role.ADMIN))
        if exists is None and settings.bootstrap_admin_username and settings.bootstrap_admin_email and settings.bootstrap_admin_password:
            db.add(User(username=settings.bootstrap_admin_username, email=settings.bootstrap_admin_email,
                        hashed_password=hash_password(settings.bootstrap_admin_password), role=Role.ADMIN))
            db.flush()
        ensure_default_leave_policies(db)
        db.commit()


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}


@app.post("/auth/register", response_model=TokenOut, status_code=201, tags=["Auth"])
def register(payload: RegisterInput, db: Session = Depends(get_db)):
    user = User(username=payload.username.lower(), email=payload.email.lower(), hashed_password=hash_password(payload.password), role=Role.EMPLOYEE)
    db.add(user)
    try:
        db.flush()
        db.add(Employee(user_id=user.id, full_name=payload.full_name, designation="Employee",
                        department="Unassigned", joining_date=date.today(), salary=0))
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email is already registered")
    return {"access_token": create_access_token(user), "user": user}


@app.post("/auth/login", response_model=TokenOut, tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(func.lower(User.username) == form_data.username.lower()))
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account is inactive")
    return {"access_token": create_access_token(user), "user": user}


@app.get("/auth/me", response_model=UserOut, tags=["Auth"])
def me(user: User = Depends(get_current_user)):
    return user


@app.post("/auth/users", response_model=UserOut, status_code=201, tags=["Auth"])
def create_privileged_user(payload: AdminUserCreate, user: User = Depends(require_roles(Role.ADMIN)), db: Session = Depends(get_db)):
    account = User(username=payload.username.lower(), email=payload.email.lower(),
                   hashed_password=hash_password(payload.password), role=payload.role)
    db.add(account)
    try:
        db.flush()
        if account.role == Role.EMPLOYEE:
            employee = Employee(user_id=account.id, full_name=account.username, designation="Employee",
                                department="Unassigned", joining_date=date.today(), salary=0)
            db.add(employee)
        db.commit()
        db.refresh(account)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email is already registered")
    return account


@app.get("/auth/users", response_model=list[UserOut], tags=["Auth"])
def list_users(user: User = Depends(require_roles(Role.ADMIN)), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.username)).all()


@app.patch("/auth/users/{user_id}", response_model=UserOut, tags=["Auth"])
def update_user(user_id: int, payload: AdminUserUpdate, user: User = Depends(require_roles(Role.ADMIN)), db: Session = Depends(get_db)):
    account = db.get(User, user_id)
    if account is None:
        raise HTTPException(status_code=404, detail="User not found")
    changes = payload.model_dump(exclude_unset=True)
    if account.id == user.id and changes.get("is_active") is False:
        raise HTTPException(status_code=409, detail="You cannot deactivate your own account")
    if account.role == Role.ADMIN and changes.get("role") not in (None, Role.ADMIN):
        active_admins = db.scalar(select(func.count(User.id)).where(User.role == Role.ADMIN, User.is_active.is_(True))) or 0
        if account.is_active and active_admins <= 1:
            raise HTTPException(status_code=409, detail="At least one active administrator must remain")
    for key, value in changes.items():
        setattr(account, key, value)
    if account.role == Role.EMPLOYEE and db.scalar(select(Employee.id).where(Employee.user_id == account.id)) is None:
        db.add(Employee(user_id=account.id, full_name=account.username, designation="Employee",
                        department="Unassigned", joining_date=date.today(), salary=0))
    db.commit()
    db.refresh(account)
    return account


@app.delete("/auth/users/{user_id}", status_code=204, tags=["Auth"])
def deactivate_user(user_id: int, user: User = Depends(require_roles(Role.ADMIN)), db: Session = Depends(get_db)):
    account = db.get(User, user_id)
    if account is None:
        raise HTTPException(status_code=404, detail="User not found")
    if account.id == user.id:
        raise HTTPException(status_code=409, detail="You cannot deactivate your own account")
    if account.role == Role.ADMIN and account.is_active:
        active_admins = db.scalar(select(func.count(User.id)).where(User.role == Role.ADMIN, User.is_active.is_(True))) or 0
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="At least one active administrator must remain")
    account.is_active = False
    db.commit()


@app.get("/employees", response_model=list[EmployeeOut], tags=["Employees"])
def list_employees(search: str | None = None, department: str | None = None, status_filter: EmployeeStatus | None = Query(default=None, alias="status"),
                   user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = select(Employee).join(User)
    if user.role == Role.EMPLOYEE:
        query = query.where(Employee.user_id == user.id)
    if search:
        query = query.where(func.lower(Employee.full_name).contains(search.lower()))
    if department:
        query = query.where(func.lower(Employee.department) == department.lower())
    if status_filter:
        query = query.where(Employee.status == status_filter)
    return [employee_out(row) for row in db.scalars(query.order_by(Employee.full_name)).all()]


@app.post("/employees", response_model=EmployeeOut, status_code=201, tags=["Employees"])
def create_employee(payload: EmployeeCreate, user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    account = User(username=payload.username.lower(), email=payload.email.lower(), hashed_password=hash_password(payload.password), role=Role.EMPLOYEE)
    db.add(account)
    try:
        db.flush()
        employee = Employee(user_id=account.id, full_name=payload.full_name, designation=payload.designation,
                            department=payload.department, joining_date=payload.joining_date, salary=payload.salary)
        db.add(employee)
        db.commit()
        db.refresh(employee)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email is already registered")
    return employee_out(employee)


@app.get("/employees/{employee_id}", response_model=EmployeeOut, tags=["Employees"])
def get_employee_profile(employee_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    employee = db.get(Employee, employee_id)
    if employee is None:
        raise HTTPException(status_code=404, detail="Employee not found")
    if user.role == Role.EMPLOYEE and employee.user_id != user.id:
        raise HTTPException(status_code=403, detail="You can only view your own employee profile")
    return employee_out(employee)


@app.patch("/employees/{employee_id}", response_model=EmployeeOut, tags=["Employees"])
def update_employee(employee_id: int, payload: EmployeeUpdate, user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    employee = db.get(Employee, employee_id)
    if employee is None:
        raise HTTPException(status_code=404, detail="Employee not found")
    for key, value in payload.model_dump(exclude_unset=True, exclude_none=True).items():
        setattr(employee, key, value)
    db.commit()
    db.refresh(employee)
    return employee_out(employee)


@app.post("/attendance/check-in", response_model=AttendanceOut, status_code=201, tags=["Attendance"])
def check_in(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    employee = get_employee(db, user)
    if employee.status != EmployeeStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Inactive employees cannot check in")
    today = date.today()
    row = db.scalar(select(Attendance).where(Attendance.employee_id == employee.id, Attendance.date == today))
    if row and row.check_in:
        raise HTTPException(status_code=409, detail="You have already checked in today")
    check_in_time = datetime.now(timezone.utc)
    is_late = check_in_time.astimezone().time() > settings.attendance_late_after
    if row is None:
        row = Attendance(employee_id=employee.id, date=today, status=AttendanceStatus.PRESENT,
                         check_in=check_in_time, is_late=is_late)
        db.add(row)
    else:
        row.check_in = check_in_time
        row.status = AttendanceStatus.PRESENT
        row.is_late = is_late
    db.commit()
    db.refresh(row)
    return attendance_out(row)


@app.post("/attendance/check-out", response_model=AttendanceOut, tags=["Attendance"])
def check_out(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    employee = get_employee(db, user)
    row = db.scalar(select(Attendance).where(Attendance.employee_id == employee.id, Attendance.date == date.today()))
    if row is None or row.check_in is None:
        raise HTTPException(status_code=400, detail="Check in before checking out")
    if row.check_out:
        raise HTTPException(status_code=409, detail="You have already checked out today")
    row.check_out = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)
    return attendance_out(row)


@app.get("/attendance", response_model=list[AttendanceOut], tags=["Attendance"])
def list_attendance(employee_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    yesterday = date.today() - timedelta(days=1)
    while yesterday.weekday() >= 5:
        yesterday -= timedelta(days=1)
    active_query = select(Employee).join(User).where(Employee.status == EmployeeStatus.ACTIVE, User.is_active.is_(True))
    if user.role == Role.EMPLOYEE:
        active_query = active_query.where(Employee.user_id == user.id)
    active_employees = db.scalars(active_query).all()
    for employee in active_employees:
        existing = db.scalar(select(Attendance).where(Attendance.employee_id == employee.id, Attendance.date == yesterday))
        approved_leave = db.scalar(select(Leave.id).where(
            Leave.employee_id == employee.id, Leave.status == LeaveStatus.APPROVED,
            Leave.start_date <= yesterday, Leave.end_date >= yesterday,
        ))
        if existing is None and approved_leave is None:
            db.add(Attendance(employee_id=employee.id, date=yesterday, status=AttendanceStatus.ABSENT))
    db.commit()
    query = select(Attendance)
    if user.role == Role.EMPLOYEE:
        query = query.where(Attendance.employee_id == get_employee(db, user).id)
    elif employee_id:
        query = query.where(Attendance.employee_id == employee_id)
    return [attendance_out(row) for row in db.scalars(query.order_by(Attendance.date.desc(), Attendance.id.desc())).all()]


@app.post("/attendance/mark", response_model=AttendanceOut, status_code=201, tags=["Attendance"])
def mark_attendance(payload: AttendanceMark, user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    employee = db.get(Employee, payload.employee_id)
    if employee is None:
        raise HTTPException(status_code=404, detail="Employee not found")
    row = db.scalar(select(Attendance).where(Attendance.employee_id == payload.employee_id, Attendance.date == payload.date))
    if row is None:
        row = Attendance(employee_id=payload.employee_id, date=payload.date, status=payload.status,
                         check_in=payload.check_in, check_out=payload.check_out)
        db.add(row)
    else:
        row.status, row.check_in, row.check_out = payload.status, payload.check_in, payload.check_out
        row.is_late = payload.status == AttendanceStatus.LATE
    if payload.status in (AttendanceStatus.ABSENT, AttendanceStatus.HALF_DAY):
        notify(db, employee.user_id, "Attendance updated",
               f"Your attendance for {payload.date} was marked {payload.status.value.lower().replace('_', ' ')}.")
    db.commit()
    db.refresh(row)
    return attendance_out(row)


@app.get("/leaves", response_model=list[LeaveOut], tags=["Leaves"])
def list_leaves(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = select(Leave)
    if user.role == Role.EMPLOYEE:
        query = query.where(Leave.employee_id == get_employee(db, user).id)
    return [leave_out(row) for row in db.scalars(query.order_by(Leave.created_at.desc())).all()]


@app.post("/leaves", response_model=LeaveOut, status_code=201, tags=["Leaves"])
def apply_leave(payload: LeaveCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    employee = get_employee(db, user)
    if employee.status != EmployeeStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Inactive employees cannot apply for leave")
    ensure_default_leave_policies(db)
    ensure_leave_balances(db, employee.id)
    requested_days = leave_days(payload.start_date, payload.end_date)
    balance = db.scalar(select(LeaveBalance).where(
        LeaveBalance.employee_id == employee.id, LeaveBalance.leave_type == payload.leave_type,
    ))
    if balance is None:
        raise HTTPException(status_code=409, detail="No leave policy is configured for this leave type")
    pending_days = sum(
        leave_days(row.start_date, row.end_date)
        for row in db.scalars(select(Leave).where(
            Leave.employee_id == employee.id, Leave.leave_type == payload.leave_type,
            Leave.status == LeaveStatus.PENDING,
        )).all()
    )
    if requested_days + pending_days > balance.remaining_days:
        raise HTTPException(status_code=409, detail="Requested leave exceeds your available balance")
    overlap = db.scalar(select(Leave.id).where(
        Leave.employee_id == employee.id,
        Leave.status.in_([LeaveStatus.PENDING, LeaveStatus.APPROVED]),
        Leave.start_date <= payload.end_date, Leave.end_date >= payload.start_date,
    ))
    if overlap is not None:
        raise HTTPException(status_code=409, detail="This request overlaps an existing leave request")
    row = Leave(employee_id=employee.id, **payload.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return leave_out(row)


@app.patch("/leaves/{leave_id}", response_model=LeaveOut, tags=["Leaves"])
def review_leave(leave_id: int, payload: LeaveReview, user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    row = db.get(Leave, leave_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Leave request not found")
    if row.status != LeaveStatus.PENDING:
        raise HTTPException(status_code=409, detail="Only pending leave requests can be reviewed")
    if payload.status == LeaveStatus.APPROVED:
        ensure_leave_balances(db, row.employee_id)
        days = leave_days(row.start_date, row.end_date)
        result = db.execute(
            update(LeaveBalance)
            .where(
                LeaveBalance.employee_id == row.employee_id,
                LeaveBalance.leave_type == row.leave_type,
                LeaveBalance.remaining_days >= days,
            )
            .values(remaining_days=LeaveBalance.remaining_days - days)
        )
        if result.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="Insufficient leave balance to approve this request")
    row.status = payload.status
    notify(db, row.employee.user_id, f"Leave {payload.status.value.lower()}",
           f"Your {row.leave_type.value.lower()} leave request from {row.start_date} to {row.end_date} was {payload.status.value.lower()}.")
    db.commit()
    db.refresh(row)
    return leave_out(row)


@app.get("/leave-policies", response_model=list[LeavePolicyOut], tags=["Leaves"])
def list_leave_policies(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ensure_default_leave_policies(db)
    db.commit()
    return db.scalars(select(LeavePolicy).order_by(LeavePolicy.leave_type)).all()


@app.post("/leave-policies", response_model=LeavePolicyOut, status_code=201, tags=["Leaves"])
def create_leave_policy(payload: LeavePolicyCreate, user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    if db.scalar(select(LeavePolicy.id).where(LeavePolicy.leave_type == payload.leave_type)) is not None:
        raise HTTPException(status_code=409, detail="A policy already exists for this leave type")
    policy = LeavePolicy(**payload.model_dump())
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@app.patch("/leave-policies/{policy_id}", response_model=LeavePolicyOut, tags=["Leaves"])
def update_leave_policy(policy_id: int, payload: LeavePolicyUpdate, user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    policy = db.get(LeavePolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Leave policy not found")
    exceeds_balance = db.scalar(select(LeaveBalance.id).where(
        LeaveBalance.leave_type == policy.leave_type,
        LeaveBalance.remaining_days > payload.total_days_allowed,
    ))
    if exceeds_balance is not None:
        raise HTTPException(status_code=409, detail="The allowance cannot be lower than an existing employee balance")
    policy.total_days_allowed = payload.total_days_allowed
    db.commit()
    db.refresh(policy)
    return policy


@app.delete("/leave-policies/{policy_id}", status_code=204, tags=["Leaves"])
def delete_leave_policy(policy_id: int, user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    policy = db.get(LeavePolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Leave policy not found")
    in_use = db.scalar(select(LeaveBalance.id).where(LeaveBalance.leave_type == policy.leave_type))
    has_requests = db.scalar(select(Leave.id).where(Leave.leave_type == policy.leave_type))
    if in_use is not None or has_requests is not None:
        raise HTTPException(status_code=409, detail="A leave policy with employee balances cannot be deleted")
    db.delete(policy)
    db.commit()


@app.get("/leave-balances", response_model=list[LeaveBalanceOut], tags=["Leaves"])
def list_leave_balances(employee_id: int | None = None, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role == Role.EMPLOYEE:
        employee = get_employee(db, user)
        employee_id = employee.id
    elif employee_id is None:
        raise HTTPException(status_code=422, detail="employee_id is required for HR and administrators")
    if db.get(Employee, employee_id) is None:
        raise HTTPException(status_code=404, detail="Employee not found")
    ensure_default_leave_policies(db)
    ensure_leave_balances(db, employee_id)
    db.commit()
    rows = db.scalars(select(LeaveBalance).where(LeaveBalance.employee_id == employee_id)).all()
    policies = {policy.leave_type: policy.total_days_allowed for policy in db.scalars(select(LeavePolicy)).all()}
    return [
        {"id": row.id, "employee_id": row.employee_id, "leave_type": row.leave_type,
         "remaining_days": row.remaining_days, "total_days_allowed": policies.get(row.leave_type, row.remaining_days)}
        for row in rows
    ]


@app.get("/payroll", response_model=list[PayrollOut], tags=["Payroll"])
def list_payroll(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = select(Payroll)
    if user.role == Role.EMPLOYEE:
        query = query.where(Payroll.employee_id == get_employee(db, user).id)
    return [payroll_out(row) for row in db.scalars(query.order_by(Payroll.month.desc())).all()]


@app.post("/payroll", response_model=PayrollOut, status_code=201, tags=["Payroll"])
def generate_payroll(payload: PayrollCreate, user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    employee = db.get(Employee, payload.employee_id)
    if employee is None:
        raise HTTPException(status_code=404, detail="Employee not found")
    if db.scalar(select(Payroll).where(Payroll.employee_id == payload.employee_id, Payroll.month == payload.month)):
        raise HTTPException(status_code=409, detail="Payroll already exists for this employee and month")
    row = Payroll(**payload.model_dump(), net_salary=round(payload.basic_salary + payload.allowances - payload.deductions + payload.bonus, 2))
    db.add(row)
    notify(db, employee.user_id, "Payroll generated", f"Your payslip for {payload.month} is ready.")
    db.commit()
    db.refresh(row)
    return payroll_out(row)


@app.get("/payroll/summary", tags=["Payroll"])
def payroll_summary(month: str = Query(pattern=r"^\d{4}-(0[1-9]|1[0-2])$"),
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = select(Payroll).where(Payroll.month == month)
    if user.role == Role.EMPLOYEE:
        query = query.where(Payroll.employee_id == get_employee(db, user).id)
    rows = db.scalars(query).all()
    return {
        "month": month,
        "employee_count": len({row.employee_id for row in rows}),
        "basic_salary": round(sum(row.basic_salary for row in rows), 2),
        "allowances": round(sum(row.allowances for row in rows), 2),
        "bonus": round(sum(row.bonus for row in rows), 2),
        "deductions": round(sum(row.deductions for row in rows), 2),
        "net_salary": round(sum(row.net_salary for row in rows), 2),
    }


@app.get("/notifications", response_model=list[NotificationOut], tags=["Notifications"])
def list_notifications(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(select(Notification).where(Notification.user_id == user.id).order_by(Notification.created_at.desc())).all()


@app.patch("/notifications/{notification_id}/read", response_model=NotificationOut, tags=["Notifications"])
def read_notification(notification_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(Notification, notification_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Notification not found")
    row.is_read = True
    db.commit()
    db.refresh(row)
    return row


@app.get("/dashboard", tags=["Dashboard"])
def dashboard(user: User = Depends(require_roles(Role.HR, Role.ADMIN)), db: Session = Depends(get_db)):
    today = date.today()
    month = today.strftime("%Y-%m")
    return {
        "total_employees": db.scalar(select(func.count(Employee.id)).where(Employee.status == EmployeeStatus.ACTIVE)) or 0,
        "present_today": db.scalar(select(func.count(Attendance.id)).where(Attendance.date == today, Attendance.status == AttendanceStatus.PRESENT)) or 0,
        "pending_leaves": db.scalar(select(func.count(Leave.id)).where(Leave.status == LeaveStatus.PENDING)) or 0,
        "payroll_this_month": db.scalar(select(func.coalesce(func.sum(Payroll.net_salary), 0)).where(Payroll.month == month)) or 0,
        "attendance_breakdown": {state.value: db.scalar(select(func.count(Attendance.id)).where(Attendance.date == today, Attendance.status == state)) or 0 for state in AttendanceStatus},
        "leave_breakdown": {state.value: db.scalar(select(func.count(Leave.id)).where(Leave.status == state)) or 0 for state in LeaveStatus},
    }


@app.get("/admin/analytics", tags=["Dashboard"])
def admin_analytics(user: User = Depends(require_roles(Role.ADMIN)), db: Session = Depends(get_db)):
    today = date.today()
    return {
        "users_total": db.scalar(select(func.count(User.id))) or 0,
        "users_active": db.scalar(select(func.count(User.id)).where(User.is_active.is_(True))) or 0,
        "users_by_role": {
            role.value: db.scalar(select(func.count(User.id)).where(User.role == role)) or 0
            for role in Role
        },
        "attendance_records": db.scalar(select(func.count(Attendance.id))) or 0,
        "leave_requests": db.scalar(select(func.count(Leave.id))) or 0,
        "payroll_records": db.scalar(select(func.count(Payroll.id))) or 0,
        "employees_active": db.scalar(select(func.count(Employee.id)).where(Employee.status == EmployeeStatus.ACTIVE)) or 0,
        "present_today": db.scalar(select(func.count(Attendance.id)).where(
            Attendance.date == today, Attendance.status.in_([AttendanceStatus.PRESENT, AttendanceStatus.LATE]),
        )) or 0,
    }
