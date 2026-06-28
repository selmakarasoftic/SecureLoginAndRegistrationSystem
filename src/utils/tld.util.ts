let tldSet: Set<string> = new Set();

export const loadTlds = async () => {
  const response = await fetch(
    "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
  );

  const text = await response.text();

  const lines = text.split("\n");

  // skip first line (# Version...)
  tldSet = new Set(
    lines
      .slice(1)
      .map((tld) => tld.trim().toLowerCase())
      .filter((tld) => tld.length > 0)
  );

  console.log(`Loaded ${tldSet.size} TLDs`);
};

export const isValidTldFromIana = (email: string): boolean => {
  const tld = email.split(".").pop()?.toLowerCase();

  if (!tld) return false;

  return tldSet.has(tld);
};