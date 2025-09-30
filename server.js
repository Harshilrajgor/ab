require('dotenv').config();
const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '2mb' }));

const PORT = process.env.PORT || 4000;
const GOOGLE_KEY = (process.env.GOOGLE_SAFE_BROWSING_API_KEY || '').trim();
const LT_URL = process.env.LANGUAGETOOL_API_URL || 'https://api.languagetool.org/v2/check';

// ------------------- FILTER FUNCTION -------------------
function filterGrammarIssues(issues) {
  if (!issues || !issues.matches) return [];

  return issues.matches
    .filter(i => i.severity === 'error')                   // only serious errors
    .filter(i => i.message && i.message.trim().length > 5) // ignore tiny messages
    .filter(i => i.context && i.context.trim().length > 10) // ignore very short context
    .filter(i => !/^MORFOLOGIK_RULE_EN_US$/.test(i.ruleId)) // ignore most false spelling positives
    .filter(i => !/^COMMA_PARENTHESIS_WHITESPACE$/.test(i.ruleId)) // minor spacing
    .filter(i => !/^SEND_AN_EMAIL$/.test(i.ruleId))      // style suggestions
    .filter(i => !/^MISSING_COMMA_AFTER_YEAR$/.test(i.ruleId)) // date comma suggestions
    .filter(i => !/^EN_DASH_RULE$/.test(i.ruleId))       // optional: ignore dash style
    .filter(i => !/^EN_QUOTES$/.test(i.ruleId));        // ignore quotes style
}

// ------------------- HELPER FUNCTIONS -------------------
function heuristicLinkCheck(url) {
  const lower = (url || '').toLowerCase();
  const reasons = [];
  const suspiciousTokens = [
    'verify', 'login', 'confirm', 'secure', 'account',
    'update', 'reset', 'bank', 'paypal', 'signin',
    'claim', 'won', 'congrats'
  ];
  suspiciousTokens.forEach(tok => {
    if (lower.includes(tok)) reasons.push(`contains "${tok}"`);
  });
  if (lower.includes('xn--')) reasons.push('punycode / idn suspicious');
  const oddTlds = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq'];
  oddTlds.forEach(t => { if (lower.endsWith(t)) reasons.push(`tld ${t}`); });
  return reasons;
}

async function googleSafeBrowsingLookup(urls = []) {
  if (!GOOGLE_KEY) return { success: true, matches: [] };
  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`;
  const body = {
    client: { clientId: "mailshield", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: [
        "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: urls.map(u => ({ url: u }))
    }
  };
  try {
    const resp = await axios.post(apiUrl, body, { timeout: 15000 });
    return { success: true, matches: resp.data && resp.data.matches ? resp.data.matches : [] };
  } catch (err) {
    console.warn('SafeBrowsing API error:', err.message || err);
    return { success: false, error: err.response ? err.response.data : err.message };
  }
}

async function languageToolCheck(text) {
  try {
    const params = new URLSearchParams();
    params.append('text', text);
    params.append('language', 'en-US');
    const resp = await axios.post(LT_URL, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 20000
    });
    return { success: true, data: resp.data };
  } catch (err) {
    console.warn('LanguageTool error:', err.message || err);
    return { success: false, error: err.response ? err.response.data : err.message };
  }
}

// ------------------- MAIN ANALYZE ROUTE -------------------
app.post('/api/analyze', async (req, res) => {
  try {
    const { payload, options } = req.body;
    if (!payload) return res.status(400).json({ success: false, error: 'Missing payload' });

    const links = Array.isArray(payload.links) ? payload.links.slice(0, 50) : [];
    const text = (payload.text || '').slice(0, 30000);
    const subject = payload.subject || '';
    const snippet = payload.snippet || (text.slice(0, 200));

    const heuristicResults = [];
    const suspiciousLinks = [];

    // ------------------- LINK SCANNING -------------------
    if (options && options.linkScanner) {
      for (const url of links) {
        const reasons = heuristicLinkCheck(url);
        if (reasons.length) heuristicResults.push({ url, reasons });
      }

      const sb = await googleSafeBrowsingLookup(links);
      if (sb.success && Array.isArray(sb.matches) && sb.matches.length) {
        sb.matches.forEach(m => {
          const entryUrl = (m && m.threat && m.threat.url)
            ? m.threat.url
            : (m && m.threatEntry && m.threatEntry.url)
            ? m.threatEntry.url
            : null;
          suspiciousLinks.push({ url: entryUrl || '(unknown)', reasons: ['Google Safe Browsing match: ' + (m.threatType || 'THREAT')] });
        });
      }

      heuristicResults.forEach(h => suspiciousLinks.push({ url: h.url, reasons: h.reasons }));
    }

    // ------------------- GRAMMAR CHECK -------------------
    let grammar = null;
    if (options && options.grammarChecker && text && text.length >= 10) {
      const lt = await languageToolCheck(text);
      if (lt.success) {
        grammar = { ...lt.data, matches: filterGrammarIssues(lt.data) };
      } else {
        grammar = { error: lt.error || 'LanguageTool error' };
      }
    }

    // ------------------- PHISHING CHECK -------------------
    const phishingPhrases = [
      'you won', 'claim your', 'click here', 'verify your account',
      'update your account', 'urgent', 'congratulations', 'prize', 'winner'
    ];
    const textLow = (text || '').toLowerCase();
    const foundPhrases = phishingPhrases.filter(p => textLow.includes(p));

    // ------------------- OVERALL STATUS -------------------
    let overall = 'safe';
    if (suspiciousLinks.length > 0 || foundPhrases.length > 0) {
      overall = 'suspicious';
    } else if (grammar && grammar.matches && grammar.matches.length > 15) { // higher threshold
      overall = 'warning';
    }

    // ------------------- DEDUPLICATE SUSPICIOUS LINKS -------------------
    const map = new Map();
    suspiciousLinks.forEach(s => map.set(s.url, (map.get(s.url) || []).concat(s.reasons || [])));
    const finalSuspicious = Array.from(map.entries()).map(([url, reasons]) => ({
      url,
      reasons: Array.from(new Set(reasons)).join(', ')
    }));

    // ------------------- SEND RESPONSE -------------------
    return res.json({
      success: true,
      payload: { subject, snippet, textLength: text.length },
      suspiciousLinks: finalSuspicious,
      grammar,
      foundPhrases,
      overall
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: err.message || String(err) });
  }
});

// ------------------- SIMPLE HEALTHCHECK -------------------
app.get('/', (req, res) => res.send('MailShield server running'));
app.listen(PORT, () => console.log(`MailShield server listening on ${PORT}`));
