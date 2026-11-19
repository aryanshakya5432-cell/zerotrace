/**
 * Optional cloud threat-intelligence lookups for URL scans.
 *
 * Both providers are strictly best-effort: a missing key, a non-2xx response or
 * a socket timeout degrades to FALLBACK and the local heuristic engine decides
 * the verdict on its own. Every outbound call is capped at 3000 ms so the
 * route stays inside its 10 s Vercel ceiling.
 */

const NETWORK_TIMEOUT_MS = 3000;

export type IntelStatus = "HIT" | "CLEAN" | "FALLBACK";

export interface IntelProviderResult {
  id: "virustotal" | "safe-browsing";
  label: string;
  status: IntelStatus;
  detail: string;
}

export interface ThreatIntelReport {
  /** True when at least one provider positively flagged the target. */
  hit: boolean;
  /** True when at least one provider actually answered (hit or clean). */
  checked: boolean;
  providers: IntelProviderResult[];
  /** Compact one-line status used in the `Cloud API Status` metadata field. */
  summary: string;
}

function makeResult(
  id: IntelProviderResult["id"],
  label: string,
  status: IntelStatus,
  detail: string,
): IntelProviderResult {
  return { id, label, status, detail };
}

async function checkVirusTotal(target: string): Promise<IntelProviderResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return makeResult(
      "virustotal",
      "VirusTotal",
      "FALLBACK",
      "VIRUSTOTAL_API_KEY not configured",
    );
  }

  const urlId = Buffer.from(target, "utf8").toString("base64url");

  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      {
        headers: { "x-apikey": apiKey, accept: "application/json" },
        signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS),
        cache: "no-store",
      },
    );

    if (response.status === 404) {
      // Not in the corpus yet: unknown, not malicious.
      return makeResult(
        "virustotal",
        "VirusTotal",
        "CLEAN",
        "URL not indexed, no detections to report",
      );
    }

    if (!response.ok) {
      return makeResult(
        "virustotal",
        "VirusTotal",
        "FALLBACK",
        `HTTP ${response.status}`,
      );
    }

    const payload = (await response.json()) as {
      data?: {
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
            undetected?: number;
            harmless?: number;
          };
        };
      };
    };

    const stats = payload.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return makeResult(
        "virustotal",
        "VirusTotal",
        "CLEAN",
        "no analysis stats published yet",
      );
    }

    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const total =
      malicious + suspicious + (stats.undetected ?? 0) + (stats.harmless ?? 0);

    if (malicious + suspicious >= 1) {
      return makeResult(
        "virustotal",
        "VirusTotal",
        "HIT",
        `${malicious} malicious / ${suspicious} suspicious of ${total} engines`,
      );
    }

    return makeResult(
      "virustotal",
      "VirusTotal",
      "CLEAN",
      `0 / ${total} engines flagged this URL`,
    );
  } catch (error) {
    const reason = error instanceof Error ? error.message : "request failed";
    return makeResult(
      "virustotal",
      "VirusTotal",
      "FALLBACK",
      `unreachable (${reason})`,
    );
  }
}

async function checkSafeBrowsing(target: string): Promise<IntelProviderResult> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return makeResult(
      "safe-browsing",
      "Google Safe Browsing",
      "FALLBACK",
      "GOOGLE_SAFE_BROWSING_API_KEY not configured",
    );
  }

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({
          client: { clientId: "zerotrace", clientVersion: "2.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: target }],
          },
        }),
        signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS),
        cache: "no-store",
      },
    );

    if (!response.ok) {
      return makeResult(
        "safe-browsing",
        "Google Safe Browsing",
        "FALLBACK",
        `HTTP ${response.status}`,
      );
    }

    const payload = (await response.json()) as {
      matches?: Array<{ threatType?: string }>;
    };

    const matches = payload.matches ?? [];
    if (matches.length > 0) {
      const types = [
        ...new Set(matches.map((match) => match.threatType).filter(Boolean)),
      ];
      return makeResult(
        "safe-browsing",
        "Google Safe Browsing",
        "HIT",
        types.length > 0 ? types.join(", ") : "threat match returned",
      );
    }

    return makeResult(
      "safe-browsing",
      "Google Safe Browsing",
      "CLEAN",
      "no threat list match",
    );
  } catch (error) {
    const reason = error instanceof Error ? error.message : "request failed";
    return makeResult(
      "safe-browsing",
      "Google Safe Browsing",
      "FALLBACK",
      `unreachable (${reason})`,
    );
  }
}

export async function checkThreatIntel(
  target: string,
): Promise<ThreatIntelReport> {
  const results = await Promise.allSettled([
    checkVirusTotal(target),
    checkSafeBrowsing(target),
  ]);

  const providers = results.map((result, index) =>
    result.status === "fulfilled"
      ? result.value
      : makeResult(
          index === 0 ? "virustotal" : "safe-browsing",
          index === 0 ? "VirusTotal" : "Google Safe Browsing",
          "FALLBACK",
          "lookup crashed",
        ),
  );

  const hit = providers.some((provider) => provider.status === "HIT");
  const checked = providers.some((provider) => provider.status !== "FALLBACK");

  const summary = providers
    .map((provider) => {
      if (provider.status === "HIT") {
        return `${provider.label}: HIT — ${provider.detail}`;
      }
      if (provider.status === "CLEAN") {
        return `${provider.label}: CLEAN`;
      }
      return `${provider.label}: FALLBACK (${provider.detail})`;
    })
    .join(" · ");

  return {
    hit,
    checked,
    providers,
    summary: checked ? summary : `${summary} — local heuristics only`,
  };
}
