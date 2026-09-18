/**
 * Standardized forensic formatting and truncation utilities for MailTraceAI.
 * Formats hashes, URLs, domains, email addresses, and IPv6 while preserving
 * contextual semantics and security defanging.
 */

/**
 * Defang a URL, IP, or domain for safe display without execution or link activation.
 */
export const defang = (val?: string): string => {
  if (!val) return '';
  return val
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
};

/**
 * Truncate a hash or hexadecimal string in the middle (e.g. SHA-256).
 * Example: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
 * becomes: `e3b0c442...7852b855`
 */
export const truncateMiddle = (
  str?: string,
  leadChars: number = 8,
  tailChars: number = 8
): string => {
  if (!str) return '';
  if (str.length <= leadChars + tailChars + 3) return str;
  return `${str.slice(0, leadChars)}...${str.slice(-tailChars)}`;
};

/**
 * Truncate an email address intelligently:
 * Keeps the username start and domain, or standard tail truncation.
 * Example: `very-long-executive-sender-name@subdomain.corporate.com`
 * becomes: `very-long...corporate.com`
 */
export const truncateEmail = (email?: string, maxLen: number = 32): string => {
  if (!email) return '';
  if (email.length <= maxLen) return email;

  const atIdx = email.lastIndexOf('@');
  if (atIdx === -1) {
    return `${email.slice(0, maxLen - 3)}...`;
  }

  const user = email.slice(0, atIdx);
  const domain = email.slice(atIdx + 1);

  if (domain.length >= maxLen - 6) {
    return `${user.slice(0, 4)}...@${domain.slice(0, maxLen - 12)}...`;
  }

  const availableForUser = maxLen - domain.length - 4;
  if (availableForUser > 3) {
    return `${user.slice(0, availableForUser)}...@${domain}`;
  }

  return `${email.slice(0, maxLen - 3)}...`;
};

/**
 * Truncate a URL intelligently:
 * Defangs the protocol and domain, and collapses excessive query strings / deep paths.
 * Example: `https://login.m1crosoft.com/auth/login?client_id=12345&response_type=code`
 * becomes: `hxxps://login[.]m1crosoft[.]com/auth/...`
 */
export const truncateUrl = (
  url?: string,
  maxLen: number = 44,
  shouldDefang: boolean = true
): string => {
  if (!url) return '';
  const displayUrl = shouldDefang ? defang(url) : url;
  if (displayUrl.length <= maxLen) return displayUrl;

  try {
    // Try URL parsing on raw
    const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
    const host = shouldDefang ? defang(parsed.hostname) : parsed.hostname;
    const protocol = shouldDefang ? (parsed.protocol === 'https:' ? 'hxxps://' : 'hxxp://') : parsed.protocol + '//';
    
    if (parsed.pathname && parsed.pathname !== '/') {
      const pathSegments = parsed.pathname.split('/').filter(Boolean);
      const firstSegment = pathSegments[0] ? `/${pathSegments[0]}` : '';
      const base = `${protocol}${host}${firstSegment}`;
      if (base.length < maxLen - 4) {
        return `${base}/...`;
      }
    }
    
    const hostBase = `${protocol}${host}`;
    if (hostBase.length < maxLen - 3) {
      return `${hostBase}/...`;
    }
  } catch {
    // Fallback if URL parsing fails
  }

  return `${displayUrl.slice(0, maxLen - 3)}...`;
};

/**
 * Truncate a domain with optional defanging.
 */
export const truncateDomain = (
  domain?: string,
  maxLen: number = 32,
  shouldDefang: boolean = true
): string => {
  if (!domain) return '';
  const display = shouldDefang ? defang(domain) : domain;
  if (display.length <= maxLen) return display;
  return `${display.slice(0, maxLen - 3)}...`;
};

/**
 * Format an IPv6 or IPv4 address:
 * IPv6 addresses can be 39 chars long. Truncates compressed or displays subnet.
 */
export const formatIp = (ip?: string, maxLen: number = 28): string => {
  if (!ip) return '';
  const clean = ip.trim();
  if (clean.length <= maxLen) return clean;
  // If it's IPv6 (contains colons), show first and last blocks
  if (clean.includes(':')) {
    return truncateMiddle(clean, 12, 8);
  }
  return clean;
};

/**
 * Truncate email subjects with a clean ellipsis.
 */
export const truncateSubject = (subject?: string, maxLen: number = 60): string => {
  if (!subject) return 'Untitled Subject';
  if (subject.length <= maxLen) return subject;
  return `${subject.slice(0, maxLen - 3)}...`;
};
