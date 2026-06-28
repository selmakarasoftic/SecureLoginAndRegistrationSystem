import { parsePhoneNumberFromString, ParseError } from "libphonenumber-js/max";
import { promises as dns } from "dns";
import { isDisposableEmail } from "disposable-email-domains-js";
import { isValidTldFromIana } from "../utils/tld.util";

export const isValidMobilePhone = (phone: string): boolean => {
  try {
    const number = parsePhoneNumberFromString(phone, "BA");

    return Boolean(number && number.isValid() && number.getType() === "MOBILE");
  } catch (e) {
    if (e instanceof ParseError) return false;
    return false;
  }
};

export const isValidTld = (email: string): boolean => {
  return isValidTldFromIana(email);
};

export const hasMxRecords = async (email: string): Promise<boolean> => {
  try {
    const domain = email.split("@")[1];

    if (!domain) return false;

    const records = await dns.resolveMx(domain);

    return records.length > 0;
  } catch {
    return false;
  }
};

export const isDisposable = (email: string): boolean => {
  return isDisposableEmail(email);
};