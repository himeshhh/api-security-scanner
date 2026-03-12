# api-security-scanner
Automated API security testing tool

An automated *API security testing tool* built with *FastAPI, React (TypeScript), Docker, and PostgreSQL*.
The application scans API endpoints for common security vulnerabilities such as authentication issues, rate limiting weaknesses, and other potential risks.

This project demonstrates *modern secure API testing architecture* with containerized deployment and a full-stack interface.

---

# 📌 Features

*  Automated API security scanning
*  JWT-based authentication system
*  Scan result storage and analysis
*  FastAPI backend for high performance
*  React + TypeScript frontend interface
*  Dockerized environment for easy deployment
*  PostgreSQL database for persistent storage
*  Security test modules for API vulnerability detection

---

# 🏗️ Architecture

```
User
 │
 ▼
Frontend (React + Vite)
 │
 ▼
FastAPI Backend
 │
 ▼
PostgreSQL Database
```

### Components

| Component        | Technology         | Purpose                             |
| ---------------- | ------------------ | ----------------------------------- |
| Frontend         | React + TypeScript | User interface                      |
| Backend          | FastAPI            | API scanning engine                 |
| Database         | PostgreSQL         | Store users, scans, results         |
| Containerization | Docker             | Consistent development & deployment |

---

# Installation (Local Development)

### 1️⃣ Clone the repository

```
git clone https://github.com/himeshhh/api-security-scanner.git
cd api-security-scanner
```

---

### 2️⃣ Create environment variables

Create a `.env` file:

```
POSTGRES_USER=apiuser
POSTGRES_PASSWORD=apipass
POSTGRES_DB=apisecurity
SECRET_KEY=change-this-secret
```

---

### 3️⃣ Start the development environment

```
docker compose -f dev.compose.yml up --build
```

---

### 4️⃣ Access the application

Frontend

```
http://localhost:5173
```

Backend API docs

```
http://localhost:8000/docs
```

---

# 🚀 Production Deployment

Run the production containers:

```
docker compose up --build
```

Then open:

```
http://localhost
```

---

# 🗄️ Database Access

To connect to PostgreSQL inside Docker:

```
docker exec -it apisec_db_dev psql -U apiuser -d apisecurity
```

Useful commands:

```
\dt
SELECT * FROM users;
SELECT * FROM scans;
SELECT * FROM test_results;
```

---

# 🔎 How the Scanner Works

1. User registers and logs in.
2. A scan request is submitted with a target API URL.
3. The backend executes vulnerability tests.
4. Results are stored in the database.
5. The frontend displays scan results.

Security tests may include:

* Rate limit detection
* Authentication validation
* API misuse patterns
* Input handling checks

---

# 🧑‍💻 Development Commands

Start development:

```
docker compose -f dev.compose.yml up
```

Stop containers:

```
docker compose down
```

View logs:

```
docker compose logs -f
```

---

# 📜 License

MIT License

---

#  Author

Replace with your information:

```
Himesh
Cybersecurity Student
GitHub: https://github.com/himeshhh
```

---

#  Contributions

Pull requests are welcome.
For major changes, please open an issue first to discuss improvements.

---

# ⚠️ Disclaimer

This tool is intended **for educational and authorized security testing purposes only**.
Do not use it to scan systems without proper permission.
