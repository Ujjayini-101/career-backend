// --------- server.js ----------
import express from "express";
import axios from "axios";
import cors from "cors";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { PDFDocument } from "pdf-lib"; 
dotenv.config();
const app = express();

// ---------- Configuration ----------
const PORT = process.env.PORT || 3000;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const MODEL = process.env.GEMINI_MODEL || "gemini-2.5-pro";
const MAX_PROMPT_CHARS = parseInt(process.env.MAX_PROMPT_CHARS || "4000", 10);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000,https://viscaraiassist-5e2c5.web.app")
  .split(",").map(s => s.trim());
const AXIOS_TIMEOUT = parseInt(process.env.AXIOS_TIMEOUT_MS || "180000", 10);

// ---------- Middlewares ----------
app.use(express.json({ limit: "6mb" })); 
app.use(morgan("dev"));
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1) return callback(null, true);
    console.warn("Blocked CORS origin:", origin);
    return callback(new Error("CORS not allowed"), false);
  }
}));
app.use(rateLimit({ windowMs: 60 * 1000, max: 120 }));

// ---------- Helpers ----------
function sanitizeText(t) {
  if (!t) return "";
  return String(t).replace(/[\u0000-\u001f\u007f-\u009f]/g, "").trim();
}
function maskKey(k) {
  if (!k) return "(missing)";
  return k.slice(0, 4) + "..." + k.slice(-4);
}

// ------- buffer parsing ---------
async function extractPdfTextBestEffort(buffer) {
  try {
   
    try {
      const pdfDoc = await PDFDocument.load(buffer);
      let text = "";
      const pages = pdfDoc.getPages();
      for (const page of pages) {
        if (typeof page.getTextContent === "function") {
          try {
            const content = await page.getTextContent();
            if (content && typeof content.items !== "undefined") {
              const pageText = (content.items || []).map(i => {
                if (typeof i.str === "string") return i.str;
                return String(i).replace(/\s+/g, " ");
              }).join(" ");
              text += pageText + "\n";
            }
          } catch (e) { 
          }
        }
      }
      if (typeof text === "string" && text.trim().length > 10) {
        return text.replace(/\s+/g, " ").trim();
      }
    } catch (e) {
    }

    // --------- Imports dynamically pdf-parse and parse the buffer directly ----------
    try {
      const mod = await import("pdf-parse");
      const pdfParse = mod.default || mod;
      const parsed = await pdfParse(buffer);
      if (parsed && parsed.text) {
        return String(parsed.text || "").replace(/\s+/g, " ").trim();
      }
    } catch (e) {
      console.warn("pdf-parse fallback failed:", e?.message || e);
    }

    // ----------- trying to decode some text which pdf contains -----------
    try {
      const maybeText = buffer.toString("utf8");
      if (maybeText && maybeText.length > 20) {
        return maybeText.replace(/\s+/g, " ").trim().slice(0, 20000);
      }
    } catch (e) {
    }

    return ""; 
  } catch (err) {
    console.warn("extractPdfTextBestEffort error:", err?.message || err);
    return "";
  }
}

// ---------- Helpers ----------
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// --------- Post to Gemini endpoint with simple retry or backoff for transient errors ----------
async function geminiPostWithRetries(url, payload, opts = {}) {
  const totalAttempts = typeof opts.attempts === 'number' ? opts.attempts : 3;
  const retryDelayMs = typeof opts.delayMs === 'number' ? opts.delayMs : 2000;

  let lastErr = null;
  for (let attempt = 1; attempt <= totalAttempts; attempt++) {
    try {
      const r = await axios.post(url, payload, { timeout: AXIOS_TIMEOUT, headers: { "Content-Type": "application/json" } });
      return r;
    } catch (e) {
      lastErr = e;
      // --------- If axios has a response then check status ----------
      const status = e.response && e.response.status ? e.response.status : null;
      const dataMsg = e.response && e.response.data ? JSON.stringify(e.response.data).slice(0,1200) : '';

      // ---------- If it's a client error do not retry ---------
      if (status && status >= 400 && status < 500 && status !== 429) {
        throw e;
      }

      // ----------- If this is the last attempt then break and rethrow below -----------
      if (attempt === totalAttempts) break;
      console.warn(`Gemini call attempt ${attempt} failed (${status || e.code || e.message}). Retrying in ${retryDelayMs}ms...`, dataMsg);
      await sleep(retryDelayMs);
    }
  }

  // ---------If all attempts failed then throw the last error ----------
  throw lastErr;
}

// --------- GitHub link summary helper -----------
async function fetchGitHubSummary(gitUrl) {
  try {
    const u = new URL(gitUrl);
    if (!u.hostname.includes("github.com")) return "";
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length === 0) return "";

    // --------- Username only ----------
    if (parts.length === 1) {
      const username = parts[0];
      const reposResp = await axios.get(`https://api.github.com/users/${username}/repos?per_page=5&sort=pushed`, { timeout: AXIOS_TIMEOUT });
      const repos = reposResp.data || [];
      let collected = `GitHub user ${username}. Top repos: ${repos.map(r => r.name).slice(0, 5).join(", ")}. `;
      if (repos.length > 0) {
        const repo = repos[0];
        try {
          const readmeResp = await axios.get(
            `https://api.github.com/repos/${username}/${repo.name}/readme`,
            { headers: { Accept: "application/vnd.github.v3.raw" }, timeout: AXIOS_TIMEOUT }
          );
          collected += `Top repo (${repo.name}) README excerpt: ${String(readmeResp.data).slice(0, 1200)}`;
        } catch (e) { /* ignore readme fetch errors */ }
      }
      return collected;
    }

    // --------- owner repo ---------
    if (parts.length >= 2) {
      const owner = parts[0], repo = parts[1];
      try {
        const readmeResp = await axios.get(
          `https://api.github.com/repos/${owner}/${repo}/readme`,
          { headers: { Accept: "application/vnd.github.v3.raw" }, timeout: AXIOS_TIMEOUT }
        );
        return `GitHub repo ${owner}/${repo} README excerpt: ${String(readmeResp.data).slice(0, 5000)}`;
      } catch (e) {
        try {
          const meta = await axios.get(`https://api.github.com/repos/${owner}/${repo}`, { timeout: AXIOS_TIMEOUT });
          return `GitHub repo ${owner}/${repo}: ${meta.data?.description || ""}`;
        } catch (e2) { return ""; }
      }
    }
    return "";
  } catch (err) {
    console.warn("fetchGitHubSummary error:", err?.message || err);
    return "";
  }
}

// ---------- Health ----------
app.get("/", (req, res) => res.send("Gemini proxy running. POST /api/gemini"));
app.get("/health", (req, res) => res.json({
  status: "ok",
  now: new Date().toISOString(),
  key: GEMINI_API_KEY ? maskKey(GEMINI_API_KEY) : "(not-set)",
  axiosTimeoutMs: AXIOS_TIMEOUT
}));

// ---------- General Gemini proxy ----------
app.post("/api/gemini", async (req, res) => {
  try {
    if (!GEMINI_API_KEY) return res.status(500).json({ error: "Missing GEMINI_API_KEY" });

    // ------- Accept `prompt` and optional `model` in the request body -----------
    let clientPrompt = req.body?.prompt || "";
    clientPrompt = sanitizeText(clientPrompt);
    if (!clientPrompt) return res.status(400).json({ error: "Empty prompt" });

    // ---------- Allow safe model override from frontend ------------
    const allowedModels = new Set(["gemini-2.5-pro", "gemini-2.5-flash"]);
    let modelToUse = String(req.body?.model || MODEL || "gemini-2.5-pro").trim();
    if (!allowedModels.has(modelToUse)) {
      modelToUse = MODEL || "gemini-2.5-pro";
    }

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${modelToUse}:generateContent?key=${GEMINI_API_KEY}`;
    const payload = { contents: [{ role: "user", parts: [{ text: clientPrompt }] }] };

    // ---------- use retries wrapper -----------
   const r = await geminiPostWithRetries(endpoint, payload, { attempts: 3, delayMs: 3000 });
   const text = r.data?.candidates?.[0]?.content?.parts?.[0]?.text || null;
   return res.json({ reply: text });

  } catch (err) {
    console.error("Gemini proxy error:", err?.message || err);
    if (err.response) {
      console.error(" Gemini response status:", err.response.status);
      try { console.error(" Gemini response data:", JSON.stringify(err.response.data).slice(0, 2000)); } catch (e) { }
    }
    if (err.code === "ECONNABORTED") {
      return res.status(504).json({ error: `Gemini API timeout after ${AXIOS_TIMEOUT} ms` });
    }
    return res.status(500).json({ error: "Gemini API error", details: err.response?.data || err.message || String(err) });
  }
});

// ---------- returns only the extracted text from resume summary ------------
app.post("/api/uploadResume", async (req, res) => {
  try {
    if (!GEMINI_API_KEY) {
      // --------- we return extracted text so frontend can call gemini -----------
      console.warn("Warning: GEMINI_API_KEY not set");
    }
    const { filename, mime, dataURL, answers } = req.body || {};
    const resume_or_link = answers?.resume_or_link || "";

    // ---------- If user provids a GitHub Url then fetch summary via server and return it ----------
    if ((!filename || !dataURL) && resume_or_link && /^https?:\/\//i.test(resume_or_link)) {
      if (resume_or_link.toLowerCase().includes("github.com")) {
        const ghSummary = await fetchGitHubSummary(resume_or_link);
        return res.json({ source: "github", resumeSummary: ghSummary || "", extractedText: "" });
      }
      // ----------- LinkedIn scraping intentionally not supported for TOS reasons -----------
      return res.status(400).json({ error: "LinkedIn scraping not supported. Please paste profile text or upload resume." });
    }

    // ------------ File upload path ------------
    if (!filename || !dataURL) return res.status(400).json({ error: "Missing file" });
    const m = String(dataURL).match(/^data:(.+);base64,(.+)$/);
    if (!m) return res.status(400).json({ error: "Invalid dataURL" });

    const fileMime = (m[1] || mime).toLowerCase();
    const fileBuffer = Buffer.from(m[2], "base64");

    console.log("📂 uploadResume: file received", {
      name: filename,
      mime: fileMime,
      size: fileBuffer.length,
      isBuffer: Buffer.isBuffer(fileBuffer)
    });

    // ----------- Extract text ----------
    let extractedText = "";
    if (fileMime.includes("pdf") || filename.toLowerCase().endsWith(".pdf")) {
      extractedText = await extractPdfTextBestEffort(fileBuffer);
    } else {
      // ----------- Trying to decode plain text so that frontend should send plain text if possible -----------
      try {
        extractedText = fileBuffer.toString("utf8");
      } catch (e) {
        extractedText = "";
      }
    }

    const extractedTrim = String(extractedText || "").slice(0, 15000);

    // ----------- Summarize resume using Gemini only if we have the key available -----------
    let resumeSummary = "";
    if (extractedTrim) {
      const summarizationPrompt = `Summarize this resume into 3–6 sentences. Include name, current title, years experience, key skills, and top projects. Max 120 words.\n\n${extractedTrim}`;
      try {
     if (GEMINI_API_KEY) {
           const sumResp = await geminiPostWithRetries(
           `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${GEMINI_API_KEY}`,
            { contents: [{ role: "user", parts: [{ text: summarizationPrompt }] }] },
            { attempts: 3, delayMs: 3000 }
               );
           resumeSummary = sumResp.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
        } else {
          // -------- If no Gemini key on server then just return a simple truncated excerpt as summary ----------
          resumeSummary = extractedTrim.slice(0, 600);
        }
      } catch (e) {
        console.warn("summarization failed on server:", e?.message || e);
        resumeSummary = extractedTrim.slice(0, 600);
      }
    }

    // ----------- only return extractedText and resumeSummary where frontend will call Gemini API for suggestions -------------
    return res.json({ source: "upload", resumeSummary, extractedText: extractedTrim });
  } catch (err) {
    console.error("uploadResume error:", err?.message || err);
    if (err.response) {
      try { console.error(" uploadResume response data:", JSON.stringify(err.response.data).slice(0, 2000)); } catch (e) { }
    }
    if (err.code === "ECONNABORTED") {
      return res.status(504).json({ error: `Gemini API timeout after ${AXIOS_TIMEOUT} ms during uploadResume` });
    }
    return res.status(500).json({ error: "uploadResume error", details: err.response?.data || err.message || String(err) });
  }
});

// ----------- Skill Gap Analysis -----------------
app.post("/api/skillGap", async (req, res) => {
  try {
    if (!GEMINI_API_KEY) return res.status(500).json({ error: "Missing GEMINI_API_KEY" });
    const { answers, role, resumeSummary } = req.body || {};
    if (!role) return res.status(400).json({ error: "Missing role" });

    const compact = answers && typeof answers === "object"
      ? Object.entries(answers).map(([k, v]) => `${k}:${v}`).join(" | ")
      : "";
    let prompt = `You are a career skill-gap analyst.
User survey: ${compact}
Target role: ${role}
Resume summary: ${resumeSummary || "N/A"}

Task:
1) Output EXACTLY one JSON object with keys:
{
 "currentSkills": ["..."],
 "skillsToLearn": ["..."],
 "matchPercent": 0-100
}
2) After the JSON, write 1–2 plain sentences explaining top 2 missing skills and one quick action to start.`;

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${GEMINI_API_KEY}`;
    const payload = { contents: [{ role: "user", parts: [{ text: prompt }] }] };
    const r = await geminiPostWithRetries(endpoint, payload, { attempts: 3, delayMs: 3000 });
    const reply = r.data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    return res.json({ reply });
  } catch (err) {
    console.error("skillGap error:", err?.message || err);
    if (err.response) {
      try { console.error(" skillGap response data:", JSON.stringify(err.response.data).slice(0, 2000)); } catch (e) { }
    }
    if (err.code === "ECONNABORTED") {
      return res.status(504).json({ error: `Gemini API timeout after ${AXIOS_TIMEOUT} ms during skillGap` });
    }
    return res.status(500).json({ error: "skillGap error", details: err.response?.data || err.message || String(err) });
  }
});

app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
