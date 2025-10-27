import express from "express";
import maxmind from "maxmind";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5000;

let cityLookup;

async function initGeoIP() {
  try {
    cityLookup = await maxmind.open(path.join(__dirname, "GeoLite2-City.mmdb"));
    console.log("✅ GeoIP database loaded successfully");
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

    const response = {
      ip,
      country: geo.country?.iso_code || "Unknown",
      region: geo.subdivisions?.[0]?.names?.en || "Unknown",
      city: geo.city?.names?.en || "Unknown",
      latitude: geo.location?.latitude || null,
      longitude: geo.location?.longitude || null,
    };

    const ALLOWED_IPS = ["49.206.100.25"];
    const ALLOWED_COUNTRIES = ["IN", "MY"];

    const allowed =
      ALLOWED_IPS.includes(response.ip) ||
      ALLOWED_COUNTRIES.includes(response.country);

    console.log(
      `${allowed ? "✅" : "❌"} Access ${
        allowed ? "granted" : "denied"
      } for ${ip} (${response.country})`
    );

    res.json({ allowed, ...response });
  } catch (error) {
    console.error("❌ Error:", error.message);
    res.status(500).json({ error: "Geolocation error" });
  }
});

initGeoIP().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ GeoIP server running at http://localhost:${PORT}`);
    console.log(`🧪 Test: http://localhost:${PORT}/check-access`);
  });
});
