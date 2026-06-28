const COMMON_PASSWORDS = new Set([
  "password",
  "password1",
  "password12",
  "password123",
  "password123!",
  "admin123",
  "admin123!",
  "qwerty123",
  "qwerty123!",
  "welcome123",
  "welcome123!",
  "letmein123",
  "letmein123!",
  "user12345",
  "user12345!",
  "test12345",
  "test12345!",
  "changeme123",
  "changeme123!",
]);

export function validatePassword(password: string): string[] {
  const errors: string[] = [];

  if (password.length < 8) {
    errors.push("Password must be at least 8 characters.");
  }

  if (!/[A-Z]/.test(password)) {
    errors.push("Must contain uppercase letter.");
  }

  if (!/[a-z]/.test(password)) {
    errors.push("Must contain lowercase letter.");
  }

  if (!/[0-9]/.test(password)) {
    errors.push("Must contain number.");
  }

  if (!/[^A-Za-z0-9]/.test(password)) {
    errors.push("Must contain special character.");
  }

  const normalized = password.toLowerCase().trim();

  if (COMMON_PASSWORDS.has(normalized)) {
    errors.push("Password is too common. Choose a less predictable password.");
  }

  return errors;
}
