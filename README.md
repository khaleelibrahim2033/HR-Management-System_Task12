# WorkSphere HRMS

WorkSphere is a full-stack HR management system built with FastAPI, SQLAlchemy, SQLite, and React. Phase 2 adds server-enforced role-based authorization, employee self-service, leave policies and balances, late/absent attendance handling, expanded payroll breakdowns, and administrator user management.

## Requirements

- Python 3.11+
- Node.js 20+

## Start the API

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set a unique `JWT_SECRET_KEY` of at least 32 characters in `backend/.env` (for example, generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`). To enable HR administration, also set all three `BOOTSTRAP_ADMIN_*` values to your chosen administrator credentials. Then run:

```powershell
uvicorn app.main:app --reload
```

The API and interactive docs are available at `http://localhost:8000` and `http://localhost:8000/docs`.

The optional `BOOTSTRAP_ADMIN_*` settings create one administrator if no admin account exists. After login, an administrator can create accounts, change roles, and deactivate users from User management or the `/auth/users` API. Public registration always creates an employee and cannot select a privileged role. HR/Admin accounts can onboard employee accounts from the Employees screen.

JWT role claims are checked against the current active database account on each authenticated request; role changes and deactivation invalidate previously issued tokens. HR/Admin can manage employee records, review leave, view attendance, and generate payroll. Employees only receive their own profile, attendance, leave, and payroll data. Administrator analytics and user-role management are admin-only.

Leave policies are initialized with 10 sick, 10 casual, and 15 paid days for a new database. Approved requests deduct calendar days from the employee balance; pending requests reserve available capacity. Attendance check-ins after `ATTENDANCE_LATE_AFTER` (09:00 by default) in server-local time are marked late. Missing attendance is automatically recorded for the previous working day when attendance history is requested, except when an approved leave covers that date. Existing databases are upgraded in place for the added user, attendance, and payroll fields.

## Start the web app

In a second PowerShell window:

```powershell
cd frontend
npm install
npm run dev
```

The frontend defaults to `http://localhost:8000` for the API. Set `VITE_API_URL` in `frontend/.env` to override it.

## Tests and build

```powershell
cd backend
python -m pip install pytest httpx
python -m pytest
```

```powershell
cd frontend
npm run build
```

The API uses SQLite by default. Set `DATABASE_URL` to a supported SQLAlchemy URL to use another database. `FRONTEND_ORIGINS` accepts a comma-separated list of allowed browser origins.

## Phase 1 notes

- Payroll values use the currency configured in the interface (USD in this starter); payslips show basic salary, allowances, bonus, deductions, and net salary.
- Payslips download as a simple text file.
- SQLite tables are created automatically for local development; production deployments should use managed secrets, HTTPS, a production database, and versioned schema migrations.
