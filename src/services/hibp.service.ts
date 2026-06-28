import crypto from "crypto";

export async function isPasswordPwned(password: string): Promise<boolean> {
    // sha-1 hash
    const sha1 = crypto
        .createHash("sha1")
        .update(password)
        .digest("hex")
        .toUpperCase();

    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);

    if (!res.ok) {
        throw new Error("HIBP API error");
    }

    const data = await res.text();

    // check if suffix exists
    return data
  .split("\n")
  .some((line) => line.split(":")[0] === suffix);
}