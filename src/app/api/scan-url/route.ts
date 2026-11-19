import dns from "node:dns/promises";
import tls from "node:tls";

import { clampScore, verdictFromScore } from "@/lib/risk";
import type { ScanCheck, ScanResult } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 10;

/** Hard ceiling for every outbound socket / resolver call (Vercel-safe). */
const NETWORK_TIMEOUT_MS = 3000;

const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "rb.gy",
  "cutt.ly",
];

const PHISHING_KEYWORDS = [
  "login",
  "verify",
  "kyc",
  "update",
  "bank",
  "sbi",
  "hdfc",
  "paytm",
  "g00gle",
  "amaz0n",
];

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^\[?[0-9a-f:]+\]?$/i;

interface HostParts {
  host: string;
  protocol: string;
  /** Text the victim is meant to read before the `@` (authority or path). */
  decoyUserInfo: string | null;
  /** Host-like string that appears after an `@` inside the path. */
  trapHost: string | null;
}

/**
 * Extracts the host the browser would actually connect to. Everything before a
 * `@` in the authority block is treated as credential redirection bait.
 */
function parseHost(rawTarget: string): HostParts {
  const trimmed = rawTarget.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  let protocol = "https:";
  let parsedHost = "";

  try {
    const parsed = new URL(withScheme);
    protocol = parsed.protocol;
    parsedHost = parsed.hostname.toLowerCase();
  } catch {
    parsedHost = withScheme
      .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
      .split(/[/?#]/)[0]
      .split(":")[0]
      .toLowerCase();
  }

  const afterScheme = withScheme.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const authority = afterScheme.split(/[/?#]/)[0];
  const authorityAt = authority.lastIndexOf("@");

  // Classic user-info trap: http://user:pass@real-host.tld/
  if (authorityAt >= 0) {
    return {
      host: authority.slice(authorityAt + 1).split(":")[0].toLowerCase(),
      protocol,
      decoyUserInfo: authority.slice(0, authorityAt),
      trapHost: null,
    };
  }

  // Path-level trap: http://1.2.3.4/sbi-kyc-verify@secure-login.xyz
  const beforeQuery = afterScheme.split(/[?#]/)[0];
  const pathAt = beforeQuery.lastIndexOf("@");
  if (pathAt > 0) {
    const trapHost = beforeQuery
      .slice(pathAt + 1)
      .split(/[/:]/)[0]
      .toLowerCase();
    if (trapHost) {
      return {
        host: parsedHost || authority.split(":")[0].toLowerCase(),
        protocol,
        decoyUserInfo: beforeQuery.slice(0, pathAt),
        trapHost,
      };
    }
  }

  return {
    host: parsedHost || authority.split(":")[0].toLowerCase(),
    protocol,
    decoyUserInfo: null,
    trapHost: null,
  };
}

function isIpHost(host: string): boolean {
  return IPV4.test(host) || IPV6.test(host);
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Timed out after ${ms}ms`)),
      ms,
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

interface DnsVerdict {
  resolved: boolean;
  address: string;
  detail: string;
}

async function resolveDns(host: string): Promise<DnsVerdict> {
  if (!host) return { resolved: false, address: "—", detail: "No hostname supplied." };
  if (isIpHost(host)) {
    return {
      resolved: true,
      address: host,
      detail: "Numeric host — no DNS resolution required.",
    };
  }

  try {
    const records = await withTimeout(dns.resolve4(host), NETWORK_TIMEOUT_MS);
    if (records.length === 0) {
      return { resolved: false, address: "—", detail: `No A records returned for ${host}.` };
    }
    return {
      resolved: true,
      address: records[0],
      detail: `A record ${records[0]} answered within ${NETWORK_TIMEOUT_MS}ms.`,
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? "";
    const transient = [
      "ECONNREFUSED",
      "ETIMEOUT",
      "ESERVFAIL",
      "EREFUSED",
      "EAI_AGAIN",
    ].includes(code);

    // Some sandboxes / locked-down VPCs refuse direct c-ares queries. Fall back
    // to the OS resolver so a blocked DNS socket is not mistaken for NXDOMAIN.
    if (transient) {
      try {
        const record = await withTimeout(
          dns.lookup(host, { family: 4 }),
          NETWORK_TIMEOUT_MS,
        );
        return {
          resolved: true,
          address: record.address,
          detail: `OS resolver fallback returned ${record.address} (c-ares: ${code}).`,
        };
      } catch {
        /* fall through to the unresolved verdict */
      }
    }

    const reason = error instanceof Error ? error.message : "lookup failed";
    return {
      resolved: false,
      address: "—",
      detail: `NXDOMAIN / resolver failure (${reason}). Domain is not routable on the public web.`,
    };
  }
}

interface TlsVerdict {
  valid: boolean;
  status: string;
  detail: string;
}

function inspectTls(host: string): Promise<TlsVerdict> {
  return new Promise<TlsVerdict>((resolve) => {
    let settled = false;
    const finish = (verdict: TlsVerdict) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(verdict);
    };

    const socket = tls.connect({
      host,
      port: 443,
      servername: isIpHost(host) ? undefined : host,
      rejectUnauthorized: false,
      timeout: NETWORK_TIMEOUT_MS,
    });

    const timer = setTimeout(
      () =>
        finish({
          valid: false,
          status: "TIMEOUT",
          detail: `TLS handshake did not complete within ${NETWORK_TIMEOUT_MS}ms.`,
        }),
      NETWORK_TIMEOUT_MS,
    );

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const identityError = isIpHost(host)
        ? null
        : tls.checkServerIdentity(host, cert);

      if (!cert || Object.keys(cert).length === 0) {
        finish({
          valid: false,
          status: "NO CERTIFICATE",
          detail: "TLS listener answered without presenting a certificate.",
        });
        return;
      }

      const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
      const daysLeft = validTo
        ? Math.round((validTo.getTime() - Date.now()) / 86_400_000)
        : null;

      const issuer =
        (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || "Unknown issuer";

      if (identityError) {
        finish({
          valid: false,
          status: "HOSTNAME MISMATCH",
          detail: `Certificate does not cover ${host} (${identityError.message}).`,
        });
        return;
      }

      if (!socket.authorized) {
        finish({
          valid: false,
          status: "UNTRUSTED",
          detail: `Certificate chain rejected: ${String(socket.authorizationError)}.`,
        });
        return;
      }

      finish({
        valid: true,
        status: "VALID",
        detail: `Chain trusted (${issuer})${daysLeft !== null ? ` · expires in ${daysLeft} days` : ""}.`,
      });
    });

    socket.once("timeout", () =>
      finish({
        valid: false,
        status: "TIMEOUT",
        detail: `TLS socket timed out after ${NETWORK_TIMEOUT_MS}ms.`,
      }),
    );

    socket.once("error", (error: Error) => {
      finish({
        valid: false,
        status: "HANDSHAKE FAILED",
        detail: `No TLS listener on port 443 (${error.message}).`,
      });
    });
  });
}

function normaliseTarget(rawTarget: string): string {
  const trimmed = rawTarget.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Malformed JSON body." }, { status: 400 });
  }

  const rawTarget =
    typeof body === "object" && body !== null && "url" in body
      ? String((body as { url: unknown }).url ?? "")
      : "";

  if (!rawTarget.trim()) {
    return Response.json(
      { error: "Provide a URL to scan." },
      { status: 400 },
    );
  }

  if (rawTarget.length > 2048) {
    return Response.json(
      { error: "Target exceeds the 2048 character limit." },
      { status: 400 },
    );
  }

  const target = normaliseTarget(rawTarget);
  const { host, protocol, decoyUserInfo, trapHost } = parseHost(rawTarget);
  const checks: ScanCheck[] = [];
  let score = 0;

  const addCheck = (check: ScanCheck) => {
    checks.push(check);
    if (check.status === "FLAGGED") score += check.weight;
  };

  // 1 — Domain vs. raw IP
  const ipHost = isIpHost(host);
  addCheck({
    id: "ip-host",
    label: "Domain vs. Raw IP Address",
    status: ipHost ? "FLAGGED" : "PASS",
    detail: ipHost
      ? `Host is the literal IP ${host}. Numeric hosts skip domain reputation, TLS naming rules and takedown coverage.`
      : `Host resolves through a named domain (${host}) instead of a bare IP literal.`,
    weight: 30,
  });

  // 2 — `@` credential redirection
  addCheck({
    id: "credential-redirect",
    label: "Credential Redirection (@ symbol)",
    status: decoyUserInfo ? "FLAGGED" : "PASS",
    detail: decoyUserInfo
      ? trapHost
        ? `"${trapHost}" looks like the host, but it sits after '@' inside the path. The browser actually opens ${host}${decoyUserInfo ? ` ("${decoyUserInfo.slice(0, 40)}" is just path text)` : ""}.`
        : `Text before '@' ("${decoyUserInfo.slice(0, 48)}") is user-info, not the destination. The browser silently connects to ${host}.`
      : "No user-info block in the authority — the visible host is the real host.",
    weight: 35,
  });

  // 3 — URL length
  const tooLong = target.length > 54;
  addCheck({
    id: "url-length",
    label: "URL Length Threshold",
    status: tooLong ? "FLAGGED" : "PASS",
    detail: `${target.length} characters (threshold: 54). ${
      tooLong
        ? "Long URLs are used to bury the true host and evade static filters."
        : "Within the normal range for legitimate links."
    }`,
    weight: 10,
  });

  // 4 — Subdomain depth + hyphen abuse
  const dotCount = (host.match(/\./g) ?? []).length;
  const hyphenCount = (host.match(/-/g) ?? []).length;
  const deepSubdomain = !ipHost && dotCount > 2;
  const hyphenAbuse = hyphenCount >= 2;
  addCheck({
    id: "host-structure",
    label: "Subdomain Depth & Hyphen Abuse",
    status: deepSubdomain || hyphenAbuse ? "FLAGGED" : "PASS",
    detail: `${dotCount} dot${dotCount === 1 ? "" : "s"} · ${hyphenCount} hyphen${
      hyphenCount === 1 ? "" : "s"
    } in host. ${
      deepSubdomain
        ? "Deeply nested subdomains mimic trusted parent brands."
        : hyphenAbuse
          ? "Repeated hyphens are a classic look-alike domain pattern."
          : "Host structure matches a standard registrable domain."
    }`,
    weight: deepSubdomain && hyphenAbuse ? 22 : 12,
  });

  // 5 — Known shorteners
  const shortener = URL_SHORTENERS.find(
    (short) => host === short || host.endsWith(`.${short}`),
  );
  addCheck({
    id: "shortener",
    label: "URL Shortener Detection",
    status: shortener ? "FLAGGED" : "PASS",
    detail: shortener
      ? `${shortener} masks the final destination behind a redirector.`
      : "Host is not on the monitored shortener list (bit.ly, tinyurl.com, t.co, goo.gl, rb.gy, cutt.ly).",
    weight: 22,
  });

  // 6 — Phishing / typosquatting keywords
  const lowered = target.toLowerCase();
  const keywordHits = PHISHING_KEYWORDS.filter((word) => lowered.includes(word));
  addCheck({
    id: "phishing-keywords",
    label: "Phishing & Typosquatting Keywords",
    status: keywordHits.length > 0 ? "FLAGGED" : "PASS",
    detail:
      keywordHits.length > 0
        ? `Matched ${keywordHits.length} lure token${keywordHits.length === 1 ? "" : "s"}: ${keywordHits
            .slice(0, 6)
            .join(", ")}.`
        : "No credential-harvesting or brand-impersonation tokens found.",
    weight: Math.min(36, keywordHits.length * 12),
  });

  // 7 — Live DNS
  const dnsVerdict = await resolveDns(host);
  addCheck({
    id: "dns-resolution",
    label: "Live DNS A-Record Resolution",
    status: dnsVerdict.resolved ? "PASS" : "FLAGGED",
    detail: dnsVerdict.detail,
    weight: 15,
  });

  // 8 — Live TLS
  let tlsVerdict: TlsVerdict;
  if (protocol === "http:") {
    tlsVerdict = {
      valid: false,
      status: "NO TLS",
      detail:
        "Target is served over plain HTTP — credentials and payloads travel unencrypted.",
    };
  } else if (!dnsVerdict.resolved) {
    tlsVerdict = {
      valid: false,
      status: "UNREACHABLE",
      detail: "Domain does not resolve, so no certificate could be validated.",
    };
  } else {
    tlsVerdict = await inspectTls(host);
  }

  addCheck({
    id: "tls-certificate",
    label: "Live HTTPS / TLS Certificate",
    status: tlsVerdict.valid ? "PASS" : "FLAGGED",
    detail: tlsVerdict.detail,
    weight: 20,
  });

  const finalScore = clampScore(score);
  const verdict = verdictFromScore(finalScore);

  let threatType = "No Threat Detected";
  if (verdict !== "SAFE") {
    if (decoyUserInfo || keywordHits.length > 0) {
      threatType = "Phishing / Credential Harvest";
    } else if (shortener) {
      threatType = "Obfuscated Redirect / Shortener";
    } else if (ipHost) {
      threatType = "Direct-to-IP Infrastructure";
    } else {
      threatType = "Suspicious Infrastructure";
    }
  }

  const result: ScanResult = {
    targetType: "url",
    target,
    score: finalScore,
    verdict,
    threatType,
    metadata: {
      Domain: host || "—",
      "Resolved IP": dnsVerdict.address,
      Protocol: protocol.replace(":", "").toUpperCase(),
      "SSL Status": tlsVerdict.status,
      "URL Length": `${target.length} chars`,
    },
    checks,
    scannedAt: new Date().toISOString(),
    engine: "ZeroTrace Heuristics · DNS + TLS live probes",
  };

  return Response.json(result);
}
