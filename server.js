import express from "express";
import maxmind from "maxmind";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5000;

let cityLookup;
let asnLookup;

async function initGeoIP() {
  try {
    cityLookup = await maxmind.open(path.join(__dirname, "GeoLite2-City.mmdb"));
    console.log("✅ GeoIP City database loaded successfully");

    // Load ASN database for VPN/hosting detection
    try {
      asnLookup = await maxmind.open(path.join(__dirname, "GeoLite2-ASN.mmdb"));
      console.log("✅ GeoIP ASN database loaded successfully");
    } catch (error) {
      console.warn("⚠️ ASN database not found - VPN detection will be limited");
    }
  } catch (error) {
    console.error("❌ Failed to load GeoIP database:", error.message);
    process.exit(1);
  }
}

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  return req.socket.remoteAddress?.replace("::ffff:", "") || req.ip;
}

// VPN/Proxy detection logic
function detectVpn(ip, asnData) {
  const vpnIndicators = {
    isVpn: false,
    isProxy: false,
    isHosting: false,
    isTor: false,
    confidence: "low",
    reasons: [],
  };

  if (!asnData) {
    vpnIndicators.reasons.push("ASN data unavailable");
    return vpnIndicators;
  }

  const orgName = (asnData.autonomous_system_organization || "").toLowerCase();

  // Common VPN provider keywords
  const vpnKeywords = [
    "vpn",
    "proxy",
    "hosting",
    "datacenter",
    "cloud",
    "virtual",
    "nordvpn",
    "expressvpn",
    "surfshark",
    "protonvpn",
    "mullvad",
    "private internet access",
    "cyberghost",
    "ipvanish",
    "purevpn",
    "windscribe",
    "tunnelbear",
    "hotspot shield",
    "hide.me",
  ];

  // Cloud/hosting provider keywords
  const hostingKeywords = [
    "amazon",
    "aws",
    "azure",
    "google cloud",
    "digitalocean",
    "linode",
    "vultr",
    "ovh",
    "hetzner",
    "scaleway",
    "contabo",
  ];

  // Tor exit node detection (simplified)
  const torKeywords = ["tor", "exit node"];

  // Check for VPN indicators
  for (const keyword of vpnKeywords) {
    if (orgName.includes(keyword)) {
      vpnIndicators.isVpn = true;
      vpnIndicators.confidence = "high";
      vpnIndicators.reasons.push(`VPN keyword detected: ${keyword}`);
      break;
    }
  }

  // Check for hosting/datacenter
  for (const keyword of hostingKeywords) {
    if (orgName.includes(keyword)) {
      vpnIndicators.isHosting = true;
      vpnIndicators.confidence = "medium";
      vpnIndicators.reasons.push(`Hosting provider detected: ${keyword}`);
      break;
    }
  }

  // Check for Tor
  for (const keyword of torKeywords) {
    if (orgName.includes(keyword)) {
      vpnIndicators.isTor = true;
      vpnIndicators.confidence = "high";
      vpnIndicators.reasons.push("Tor exit node detected");
      break;
    }
  }

  // If any indicator is true, mark as proxy
  if (vpnIndicators.isVpn || vpnIndicators.isHosting || vpnIndicators.isTor) {
    vpnIndicators.isProxy = true;
  }

  return vpnIndicators;
}

app.get("/check-access", (req, res) => {
  try {
    const ip = getClientIp(req);
    console.log(`📍 Checking IP: ${ip}`);

    if (ip === "127.0.0.1" || ip === "::1" || ip === "localhost") {
      return res.json({
        allowed: false,
        ip,
        error: "Localhost IP cannot be geolocated",
      });
    }

    const geo = cityLookup.get(ip);

    if (!geo) {
      return res.json({
        allowed: false,
        ip,
        country: "Unknown",
        region: "Unknown",
        city: "Unknown",
        latitude: null,
        longitude: null,
        error: "IP not found in database",
      });
    }

    // Get ASN data for VPN detection
    const asnData = asnLookup ? asnLookup.get(ip) : null;
    const vpnCheck = detectVpn(ip, asnData);

    const response = {
      ip,
      country: geo.country?.iso_code || "Unknown",
      region: geo.subdivisions?.[0]?.names?.en || "Unknown",
      city: geo.city?.names?.en || "Unknown",
      latitude: geo.location?.latitude || null,
      longitude: geo.location?.longitude || null,
      asn: asnData?.autonomous_system_number || null,
      organization: asnData?.autonomous_system_organization || "Unknown",
      vpnDetection: vpnCheck,
    };

    const ALLOWED_IPS = ["49.206.100.25"];
    const ALLOWED_COUNTRIES = ["IN", "MY"];

    // Check if IP is allowed AND not using VPN
    const isGeoAllowed =
      ALLOWED_IPS.includes(response.ip) ||
      ALLOWED_COUNTRIES.includes(response.country);

    const isVpnBlocked = vpnCheck.isVpn || vpnCheck.isProxy;

    const allowed = isGeoAllowed && !isVpnBlocked;

    let blockReason = null;
    if (!isGeoAllowed) {
      blockReason = "Geographic restriction";
    } else if (isVpnBlocked) {
      blockReason = "VPN/Proxy detected";
    }

    console.log(
      `${allowed ? "✅" : "❌"} Access ${
        allowed ? "granted" : "denied"
      } for ${ip} (${response.country})${
        blockReason ? ` - ${blockReason}` : ""
      }`
    );

    res.json({
      allowed,
      blockReason,
      ...response,
    });
  } catch (error) {
    console.error("❌ Error:", error.message);
    res.status(500).json({ error: "Geolocation error" });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    databases: {
      city: !!cityLookup,
      asn: !!asnLookup,
    },
  });
});

initGeoIP().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ GeoIP server running at http://localhost:${PORT}`);
    console.log(`🧪 Test: http://localhost:${PORT}/check-access`);
    console.log(`💚 Health: http://localhost:${PORT}/health`);
  });
});
