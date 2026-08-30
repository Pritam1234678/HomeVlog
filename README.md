# HomeVlog

A calm, considered space to write and share vlogs. FastAPI + PostgreSQL backend with JWT cookie authentication, and a React (Vite) frontend.

## Features

- **Public** — Home, Sign in, Sign up
- **Authenticated** — Dashboard (write/edit/delete your vlogs), Feed, Vlog detail pages
- JWT auth stored in an httpOnly cookie; bcrypt password hashing
- Automatic redirect to `/dashboard` when logged-in users visit `/login` or `/signup`

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy, PostgreSQL (Aiven), PyJWT, bcrypt
- **Frontend:** React 19, Vite 8, Tailwind CSS v4, React Router 7

## Setup

### Backend

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create `.env`:

```
DATABASE_URL=postgres://user:pass@host:port/dbname?sslmode=require
SECRET_KEY=your-random-secret-key
```

Run:

```bash
uvicorn main:app --reload
```

Docs: http://127.0.0.1:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/auth`, `/users`, and `/vlogs` to `http://127.0.0.1:8000`.

## API

| Method | Route          | Description                                  |
|--------|----------------|----------------------------------------------|
| POST   | `/auth/signup` | Register with name, email, password          |
| POST   | `/auth/login`  | Login with email, password                   |
| POST   | `/auth/logout` | Logout                                       |
| GET    | `/users/me`    | Get current user (auth required)             |
| GET    | `/vlogs`       | List vlogs (auth required)                   |
| GET    | `/vlogs/{id}`  | Get a vlog (auth required)                   |
| POST   | `/vlogs`       | Create a vlog (auth required)                |
| PUT    | `/vlogs/{id}`  | Update own vlog (auth required)              |
| DELETE | `/vlogs/{id}`  | Delete own vlog (auth required)              |
# HomeVlog
