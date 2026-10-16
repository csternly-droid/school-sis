// schemes.js - generates a Kenyan CBC scheme of work by calling the Anthropic API.
// Used by the teacher endpoints in server.js. The API key stays on the server
// (ANTHROPIC_API_KEY environment variable) and is never sent to the browser.

const DEFAULT_MODEL = 'claude-haiku-5-5';   // override with the SCHEME_MODEL env var
const API_TIMEOUT_MS = 55000;               // keep under the 60s function limit in vercel.json
const MAX_FIELD_CHARS = 1500;

function cleanGrade(grade) {
  const g = String(grade || '').trim();
  const m = g.match(/^grade\s*(\d+)$/i);
  return m ? m[1] : g;
}

function gradeLabel(grade) {
  const g = cleanGrade(grade);
  return /^\d+$/.test(g) ? `Grade ${g}` : g;
}

function levelFor(grade) {
  const g = cleanGrade(grade).toLowerCase();
  if (g === 'baby class' || g === 'pp1' || g === 'pp2') return 'Pre-Primary';
  const n = Number(g);
  if (n >= 1 && n <= 3) return 'Lower Primary';
  if (n >= 4 && n <= 6) return 'Upper Primary';
  if (n >= 7 && n <= 9) return 'Junior School';
  if (n >= 10 && n <= 12) return 'Senior School';
  return '';
}

function buildSchemePrompt({ subject, grade, term, year, weeks, lessonsPerWeek }) {
  const level = levelFor(grade);
  const system = [
    'You are an experienced Kenyan teacher and curriculum specialist. You write schemes of work that follow the Competency Based Curriculum (CBC) curriculum designs published by the Kenya Institute of Curriculum Development (KICD).',
    'Use the official learning-area, strand and sub-strand names from the KICD curriculum design for the given grade wherever you know them. If you are not sure of an official name, use the closest sensible wording rather than inventing unusual terms.',
    'Never invent textbook titles, publishers or page numbers. Suggest realistic, locally available learning resources instead.',
    'Write the scheme in English, except for Kiswahili (and other language) learning areas, which should be written in that language where natural.',
    'Respond with ONLY valid JSON. No markdown, no code fences, no commentary.'
  ].join('\n');

  const user = [
    'Write a scheme of work for:',
    `- Learning area / subject: ${subject}`,
    `- Grade: ${gradeLabel(grade)}${level ? ` (${level})` : ''}`,
    `- Term: ${term} of 3, year ${year}`,
    `- Number of teaching weeks in the term: ${weeks}`,
    `- Lessons per week: ${lessonsPerWeek}`,
    '',
    'Rules:',
    `- The curriculum design covers the whole year. Divide its strands and sub-strands across the three terms in the usual way and write ONLY the content that belongs in Term ${term}.`,
    `- Produce exactly ${weeks} rows, one per week. Use the final week for revision and end-of-term assessment.`,
    '- specific_learning_outcomes: start with "By the end of the week, the learner should be able to:" then list 2-3 outcomes as a) b) c), each on its own line.',
    '- learning_experiences: 2-3 learner-centred activities, each on its own line, starting with a verb.',
    '- key_inquiry_questions: 1-2 questions.',
    '- learning_resources: realistic, locally available resources.',
    '- assessment_methods: e.g. oral questions, observation, checklist, written exercise, portfolio, project.',
    '- Keep every field concise so the whole scheme stays compact.',
    '- reflection must always be an empty string (the teacher fills it in after teaching).',
    '',
    'Return exactly this JSON shape:',
    '{"rows":[{"strand":"","sub_strand":"","specific_learning_outcomes":"","learning_experiences":"","key_inquiry_questions":"","learning_resources":"","assessment_methods":"","reflection":""}]}'
  ].join('\n');

  return { system, user };
}

// Pull the JSON object out of the model's reply, tolerating stray text or code fences.
function extractJson(text) {
  if (!text) return null;
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch (err) {
    return null;
  }
}

function str(v) {
  return String(v === undefined || v === null ? '' : v).trim().slice(0, MAX_FIELD_CHARS);
}

// Week and lesson numbers are set here (not trusted from the model) so they are always consistent.
function normaliseRows(rows, weeks, lessonsPerWeek) {
  return rows.slice(0, weeks).map((r, i) => {
    const first = i * lessonsPerWeek + 1;
    const last = (i + 1) * lessonsPerWeek;
    return {
      week: String(i + 1),
      lessons: lessonsPerWeek === 1 ? String(first) : `${first}-${last}`,
      strand: str(r && r.strand),
      sub_strand: str(r && r.sub_strand),
      specific_learning_outcomes: str(r && r.specific_learning_outcomes),
      learning_experiences: str(r && r.learning_experiences),
      key_inquiry_questions: str(r && r.key_inquiry_questions),
      learning_resources: str(r && r.learning_resources),
      assessment_methods: str(r && r.assessment_methods),
      reflection: str(r && r.reflection)
    };
  });
}

function httpError(message, status) {
  const e = new Error(message);
  e.status = status;
  return e;
}

async function generateSchemeRows(opts) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw httpError('The scheme generator is not set up yet. Ask the school admin to add the ANTHROPIC_API_KEY.', 503);
  }

  const { system, user } = buildSchemePrompt(opts);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  let status;
  let bodyText;
  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: process.env.SCHEME_MODEL || DEFAULT_MODEL,
        max_tokens: 6000,
        system,
        messages: [{ role: 'user', content: user }]
      }),
      signal: controller.signal
    });
    status = resp.status;
    bodyText = await resp.text();
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw httpError('Generating took too long. Please try again.', 504);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }

  if (status < 200 || status >= 300) {
    console.error('Anthropic API error', status, String(bodyText).slice(0, 500));
    throw httpError('The scheme generator is unavailable right now. Please try again shortly.', 502);
  }

  let data;
  try {
    data = JSON.parse(bodyText);
  } catch (err) {
    throw httpError('The scheme generator sent an unreadable reply. Please try again.', 502);
  }

  const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
  const parsed = extractJson(text);
  if (!parsed || !Array.isArray(parsed.rows) || !parsed.rows.length) {
    console.error('Scheme JSON could not be read. stop_reason:', data.stop_reason);
    throw httpError('The scheme came back incomplete. Please try again.', 502);
  }

  return normaliseRows(parsed.rows, opts.weeks, opts.lessonsPerWeek);
}

module.exports = { generateSchemeRows, buildSchemePrompt, extractJson, normaliseRows, levelFor, gradeLabel };