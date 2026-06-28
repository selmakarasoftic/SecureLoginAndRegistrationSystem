# Secure Authentication System — SSSD 2026


## 1. Project Overview

This project is a secure authentication and account-management system developed for the **Secure Software System Design (SSSD)** course. The application focuses on implementing a complete authentication flow with secure registration, login protection, email verification, multi-factor authentication, session management, password recovery, audit logging, and admin-level security controls.

The system was designed to follow the project milestone requirements and to demonstrate practical secure software development concepts, including password hashing, token-based authentication, CAPTCHA protection, OAuth-based Single Sign-On, refresh token rotation, and centralized audit logging.

---

## 2. Main Features

### User Registration and Validation

- User registration with full name, username, email, phone number, and password.
- Full name validation with length checks and protection against HTML/script tags.
- Unique username, email, and phone number validation.
- Reserved username validation, including values such as `admin`, `root`, `system`, and `support`.
- Email validation using:
  - email format checks,
  - IANA TLD validation,
  - MX record validation,
  - disposable email detection.
- Mobile phone number validation using a phone-number validation library.

### Password Security

- Password complexity validation.
- Minimum password length requirement.
- Password hashing and salting using `bcrypt`.
- Have I Been Pwned password check to reject compromised passwords.
- Password reset flow with time-limited and single-use reset links.

### Email Verification

- Verification email sent after registration.
- Verification link expires after 15 minutes.
- Verification tokens are single-use only.
- Unverified accounts cannot log in.
- Blocked accounts cannot log in.

### Login Security

- Login using either username or email.
- Secure password comparison against the stored hashed password.
- Failed login attempt tracking.
- CAPTCHA challenge after repeated failed login attempts.
- Rate limiting on sensitive authentication endpoints.

### Two-Factor Authentication 2FA

The system supports multiple second-factor methods:

- Email verification code.
- SMS verification code through Infobip integration.
- TOTP support for authenticator applications such as Google Authenticator.
- Recovery codes as a backup 2FA method.

Recovery codes are shown only once, stored hashed, and can be used only one time.

### Single Sign-On SSO

- Google OAuth login.
- GitHub OAuth login.
- SSO email must match the existing account email.
- Users must still complete 2FA after SSO authentication.
- Blocked or unverified accounts cannot log in through SSO.

### Session Management

- JWT-based authentication.
- Short-lived access tokens.
- Long-lived refresh tokens.
- Refresh token rotation on every refresh request.
- Refresh token reuse detection.
- Session invalidation on logout.
- Session records stored in the database.
- Users can view and revoke active sessions.

### Trusted Device Management

- Users can mark a device as trusted after successful login and 2FA.
- Trusted devices can bypass the 2FA step for a limited period of 10 days.
- Password login is still required even when the device is trusted.
- Trusted device data is stored in the database.
- Users can view and revoke trusted devices.

### Password Recovery

- Password reset request through registered email address.
- Unverified accounts cannot recover passwords.
- Password reset attempts are limited.
- CAPTCHA is required after repeated reset attempts.
- Reset links expire after 5 minutes and are single-use only.
- A confirmation email is sent after a successful password reset.

### Audit Logging

The system includes centralized audit logging for security-relevant actions, including:

- successful and failed login attempts,
- registration events,
- email verification events,
- 2FA setup and usage,
- SSO authentication,
- password reset and password change events,
- trusted device creation and revocation,
- session events,
- admin actions.

Each log entry can include actor information, actor role, IP address, user agent, timestamp, action, affected object, object ID, and previous object state when available.

### Admin Dashboard Features

- View users.
- Block and unblock users.
- View audit logs with filtering and pagination.
- Manage reserved usernames through CRUD operations.

---

## 3. Technology Stack

### Backend

- Node.js
- Express.js
- TypeScript
- MySQL

### Security and Authentication

- bcrypt
- JSON Web Tokens
- HTTP-only refresh token cookies
- hCaptcha
- Google OAuth
- GitHub OAuth
- TOTP authentication
- Recovery codes

### External Services

- Infobip for SMS verification
- SMTP provider for verification and password reset emails
- Have I Been Pwned API for password compromise checks


---

## 4. Project Structure

```text
sssd-2026-23004204-milestone3/
│
├── database_info/
│   ├── schema.png
│   └── script.txt
│
├── public/
│   └── login.html
│
├── scripts/
│   ├── infobip.ts
│   └── testingTooManyLogins.ts
│
├── src/
│   ├── config/
│   ├── controllers/
│   ├── docs/
│   │   └── openapi.ts
│   ├── middlewares/
│   ├── routes/
│   ├── services/
│   ├── utils/
│   ├── validators/
│   ├── app.ts
│   └── server.ts
│
├── .env.example
├── package.json
├── package-lock.json
├── tsconfig.json
└── README.md
```
---

## 5. Setup and Installation

External accounts or credentials are also required for full functionality:

- SMTP email account
- Infobip account for SMS sending
- hCaptcha site key and secret key
- Google OAuth credentials
- GitHub OAuth credentials

### Clone the Repository

```bash
git clone <repository-url>
cd sssd-2026-23004204-milestone3
```

### Install Dependencies

```bash
npm install
```
---

## 6. Database Setup

The database structure is documented in the `database_info` folder.

- `database_info/script.txt` contains the SQL statements used to create and update the database tables.
- `database_info/schema.png` contains a visual database schema overview.

To set up the database:

1. Create a MySQL database.
2. Update the database credentials in `.env`.
3. Run the SQL statements from `database_info/script.txt`.
4. Make sure the required tables exist before starting the application.

Main tables include:

- `users`
- `reserved_usernames`
- `email_verification_tokens`
- `two_factor_codes`
- `recovery_codes`
- `login_2fa_tokens`
- `password_reset_tokens`
- `trusted_devices`
- `sessions`
- `refresh_tokens`
- `audit_logs`

For testing the admin dashboard, one user account must have the `admin` role in the database.
---

## 7. Milestone Coverage
The original course repository was private and managed through the official course GitHub workflow. Because access to that repository is restricted, this repository represents a personal copy of the final project version, prepared for documentation, review, and demonstration purposes.
The project was developed in the following order:

### Milestone 1

- Node.js, Express.js, and TypeScript project setup.
- Basic `/api/health`, `/api/register`, and `/api/login` endpoints.
- OpenAPI documentation.
- SMS integration through Infobip.
- Environment variable configuration.

### Milestone 2

- MySQL database integration.
- Secure registration and password handling.
- Reserved username validation.
- HIBP password check.
- Email validation and verification.
- Login with username or email.
- Blocked and unverified account protection.
- 2FA implementation.

### Milestone 3

- Google and GitHub SSO.
- CAPTCHA protection.
- Trusted device management.
- Password recovery.
- Audit logging.
- JWT access and refresh token session management.
- Admin dashboard security controls.

---
## 8. Deployment Status

The application was prepared for deployment on a Linux-based VPS using Nginx and HTTPS. During development and testing, the project was deployed and tested in a live environment. However, the public instance may currently be stopped because of limited virtual machine resources available through the student subscription.

The application can still be run locally and redeployed using the provided environment configuration and database setup.

---

## 9. Conclusion

This project demonstrates a complete secure authentication system with multiple layers of account protection. It combines secure registration, strong password validation, email verification, 2FA, SSO, trusted devices, JWT session handling, password recovery, CAPTCHA protection, and audit logging into one application.

The system is designed to be tested locally, documented through Swagger, and deployable on a Linux VPS with Nginx and HTTPS.