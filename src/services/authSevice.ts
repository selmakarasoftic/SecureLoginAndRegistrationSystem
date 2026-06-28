import { db } from "../config/database";
import { hashPassword, comparePassword } from "../utils/password";
import { isPasswordPwned } from "./hibp.service";
import { validatePassword } from "../validators/password.validator";
import { sendVerificationEmail } from "./emailVerification.service";
import {
  isValidMobilePhone,
  hasMxRecords,
  isDisposable,
} from "../validators/register.validator";
import { isValidTldFromIana } from "../utils/tld.util";

const isValidFullName = (fullName: string) => {
  const trimmed = fullName.trim();
  return trimmed.length >= 3 && trimmed.length <= 100 && !/[<>]/.test(trimmed);
};

const isValidEmailFormat = (email: string) => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

const isValidUsername = (username: string) => {
  const trimmed = username.toLowerCase();

  return (
    trimmed.length > 3 &&
    trimmed.length <= 30 &&
    /^[a-zA-Z0-9]+$/.test(trimmed)
  );
};

const isReservedUsername = async (username: string): Promise<boolean> => {
  const [rows]: any = await db.query(
    "SELECT id FROM reserved_usernames WHERE username = ? LIMIT 1",
    [username.toLowerCase()]
  );

  return rows.length > 0;
};

export const registerUser = async (data: any) => {
  const { fullName, email, username, password, phone } = data;

  if (!fullName || !email || !username || !password || !phone) {
    return { error: "All fields are required" };
  }

  if (!isValidFullName(fullName)) return { error: "Invalid full name" };
  if (!isValidUsername(username)) return { error: "Invalid username" };

  if (await isReservedUsername(username)) {
    return { error: "Username is reserved" };
  }

  const passwordErrors = validatePassword(password);
  if (passwordErrors.length > 0) {
    return { error: passwordErrors.join(", ") };
  }

  if (!isValidEmailFormat(email)) {
    return { error: "Invalid email format" };
  }

  if (!isValidTldFromIana(email)) {
    return { error: "Invalid email TLD" };
  }

  const mxValid = await hasMxRecords(email);
  if (!mxValid) {
    return { error: "Email domain does not accept emails" };
  }

  if (isDisposable(email)) {
    return { error: "Disposable emails are not allowed" };
  }

  if (!isValidMobilePhone(phone)) {
    return { error: "Phone must be a valid mobile number" };
  }

  const pwned = await isPasswordPwned(password);
  if (pwned) {
    return { error: "Password is compromised, choose another one" };
  }

  const passwordHash = await hashPassword(password);

  try {
    const [result]: any = await db.query(
      `INSERT INTO users (full_name, email, username, password_hash, phone, role)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        fullName.trim(),
        email.toLowerCase(),
        username.toLowerCase(),
        passwordHash,
        phone,
        "user",
      ]
    );

    await sendVerificationEmail(result.insertId, email.toLowerCase());

    return {
      success: true,
      data: {
        fullName: fullName.trim(),
        email: email.toLowerCase(),
        username: username.toLowerCase(),
        phone,
        role: "user",
      },
    };
  } catch (err: any) {
    if (err.code === "ER_DUP_ENTRY") {
      return { error: "Email, username, or phone already exists" };
    }

    console.error("DATABASE ERROR:", err);
    return { error: "Registration failed" };
  }
};

export const loginUser = async (data: any) => {
  const { usernameOrEmail, password } = data;

  if (!usernameOrEmail || !password) {
    return { error: "usernameOrEmail and password are required" };
  }

  const normalized = usernameOrEmail.toLowerCase();

  const [rows]: any = await db.query(
    `SELECT * FROM users WHERE email = ? OR username = ? LIMIT 1`,
    [normalized, normalized]
  );

  if (rows.length === 0) {
    return { error: "User does not exist" };
  }

  const user = rows[0];

  if (!user.email_verified) {
    return { error: "Please verify your email before logging in" };
  }

  if (user.is_blocked) {
    return { error: "Account is blocked" };
  }

  const match = await comparePassword(password, user.password_hash);

  if (!match) {
    return { error: "Invalid credentials" };
  }

  return {
    success: true,
    requiresTwoFactor: Boolean(user.two_factor_enabled),
    requiresTwoFactorSetup: !Boolean(user.two_factor_enabled),
    twoFactorMethod: user.two_factor_method || null,
    userId: user.id,
    role: user.role || "user",
    data: {
      fullName: user.full_name,
      email: user.email,
      username: user.username,
      phone: user.phone,
      role: user.role || "user",
    },
  };
};