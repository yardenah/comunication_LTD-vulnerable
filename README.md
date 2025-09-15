# Communication LTD Application

A full-stack web application with React frontend and Express.js backend, featuring user authentication and client management.

## Project Structure

```
comunication_LTD/
├── client/          # React frontend (Vite)
├── server/          # Express.js backend
└── package.json     # Root package.json for convenience
```

## Prerequisites

- Node.js (v16 or higher)
- npm or yarn

## Installation

1. **Install all dependencies:**

   ```bash
   npm run install-all
   ```

   Or install manually:

   ```bash
   # Root dependencies
   npm install

   # Server dependencies
   cd server
   npm install

   # Client dependencies
   cd ../client
   npm install
   ```

## Environment Configuration

**Important**: Create a `.env` file in the `server/` directory with the following variables:

```bash
# Email Configuration (for password reset functionality)
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password-here
```

### Gmail App Password Setup

1. Go to your Google Account settings
2. Enable 2-Factor Authentication if not already enabled
3. Generate an App Password specifically for this application
4. Use this App Password (not your regular Gmail password) in the `.env` file

## Running the Application

### Option 1: Run both frontend and backend together

```bash
npm run dev
```

This will start:

- Backend server on `http://localhost:5000`
- Frontend development server on `http://localhost:3000`

### Option 2: Run separately

**Start the backend server:**

```bash
npm run server
# or
cd server && npm start
```

**Start the frontend development server:**

```bash
npm run client
# or
cd client && npm run dev
```

## API Endpoints

The backend provides the following API endpoints:

- `GET /api/config` - Get server configuration (password policies)
- `POST /api/register` - User registration
- `POST /api/login` - User login
- `POST /api/change-password` - Change password
- `POST /api/request-reset-password` - Request password reset
- `POST /api/reset-password` - Reset password with token
- `GET /api/clients` - Get all clients
- `POST /api/clients` - Add new client

**Interactive API Documentation**: Available at `http://localhost:5000/api-docs` (Swagger)

## Configuration

### Backend Configuration

- Port: 5000 (configurable in `server/config.js`)
- Database: SQLite (`communication_ltd.db`)
- CORS: Enabled for frontend origin (`http://localhost:3000`)

### Frontend Configuration

- Port: 3000 (configurable in `client/vite.config.js`)
- API Proxy: Configured to forward `/api` requests to backend
- Base URL: Uses relative paths for API calls

## Development

### Backend Development

- Uses nodemon for auto-restart during development
- Swagger documentation available at `http://localhost:5000/api-docs`
- Environment variables: Create `.env` file in server directory

### Frontend Development

- Vite development server with hot reload
- React Router for navigation
- API calls use relative URLs for better proxy support

## Database

The application uses SQLite with the following tables:

### Users Table

- `id` (INTEGER, PRIMARY KEY, AUTOINCREMENT)
- `username` (TEXT, UNIQUE, NOT NULL)
- `email` (TEXT, NOT NULL)
- `password` (TEXT, NOT NULL, hashed)
- `salt` (TEXT, NOT NULL, for password hashing)
- `reset_token` (TEXT, nullable)
- `reset_token_expiry` (DATETIME, nullable)

### Clients Table

- `id` (INTEGER, PRIMARY KEY)
- `fullName` (VARCHAR(100), required)
- `email` (VARCHAR(100))
- `phone` (VARCHAR(20))
- `packageName` (VARCHAR(50))
- `sector` (VARCHAR(50))
- `address` (VARCHAR(255))

### Password History Table

- `id` (INTEGER, PRIMARY KEY, AUTOINCREMENT)
- `user_id` (INTEGER, NOT NULL, FOREIGN KEY to users.id)
- `password_hash` (TEXT, NOT NULL, hashed password)
- `salt` (TEXT, NOT NULL, salt used for hashing)
- `created_at` (DATETIME, DEFAULT CURRENT_TIMESTAMP)

### Database Setup

- SQLite database file: `communication_ltd.db`
- Database is automatically created on first run
- Tables are created with proper schema on server startup
- **VS Code Extension**: Install "SQLite" by "qwtel" to view and manage the database directly in VS Code

## Security Features

- Password hashing with HMAC + Salt
- Password history validation (configurable, min 1, max 100)
- Login attempt limiting
- CORS protection
- Input validation

# Vulnerabilities Demonstration

This section demonstrates deliberate web vulnerabilities left in the project’s routes. For each example we show a simple payload, explain how it manipulates the SQL/HTML flow, and describe the real-world impact an attacker could achieve.

---

# 1. Add Client – SQL Injection + Stored XSS

**Vulnerable Route:** `POST /api/clients`

---

## (a) SQL Injection

Payload (**Full Name** field):

```sql
attacker', 'attacker@example.test', '000', 'fakePkg', 'fakeSector', 'fakeAddr'); --
```

**What this does**

- Inserts a fake client row with attacker-controlled fields
- Allows an attacker to inject arbitrary values into the database

**Why this matters**

- Fake records pollute data, can be used for impersonation, spam, or to influence reports and downstream processes
- In other contexts, a similar injection could be modified to escalate into more destructive actions (data tampering, unauthorized access)

## (b) Stored XSS

Payload (**Full Name** field):

```bash
 <img src=x onerror=alert("Hacked-XSS")>
```

**What this does**

- The application stores the string in the `clients.fullName` column without escaping
- When the clients list is later rendered into the page without HTML-encoding (e.g. using `dangerouslySetInnerHTML` or returning raw HTML), the browser executes the script
- Visible effect: a JavaScript `alert("Hacked-XSS")` will pop up for anyone viewing the page (demonstrates stored XSS)

**Why this matters**

- An attacker could run arbitrary JS in other users’ browsers (steal cookies/tokens, deface UI, perform actions on behalf of victims)
- Payload is stored and affects all future viewers

# 2. Login – SQL Injection (Authentication bypass)

**Vulnerable Route:** `POST /api/login`

---

Payload (**username** field):

```bash
 ' OR 1=1 --
```

**What this does**

- The payload closes the username string, adds an always-true condition (`1=1`) and comments out the rest, so the `WHERE` becomes true for at least one row
- The query returns a user row even without a correct password, so the attacker is considered authenticated

**Why this matters**

- Allows an attacker to bypass authentication and access other users’ accounts or application functionality
- Once authenticated, the attacker can view or manipulate sensitive data, escalate privileges, or pivot to other attacks

# 3. Register – SQL Injection (Insert fake account)

**Vulnerable Route:** `POST /api/register`

---

Payload (**username** field):

```bash
attacker', 'fake@mail.com', '1234', 'xyz'); --
```

**What this does**

- When concatenated into an `INSERT` statement, the payload closes the `fullName` value and injects attacker-controlled column values
- The remainder of the original `VALUES(...)` is commented out, so the database inserts a row with attacker-chosen fields (e.g., a fake user with a weak password)

**Why this matters**

- A new user record appears in the database with attacker-controlled username/email/password fields
- In production scenarios similar injections could be adapted for data tampering or privilege escalation

## License

MIT
