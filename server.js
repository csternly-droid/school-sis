require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const pool = require('./db');
const { signToken, requireRole } = require('./auth');

const app = express();
app.use(cors());
app.use(express.json());

// Small helper so we don't repeat try/catch everywhere
const wrap = (fn) => (req, res) => fn(req, res).catch((err) => {
  console.error(err);
  res.status(500).json({ error: 'Server error', detail: err.message });
});

// ---------- LOGIN ----------
app.post('/api/login/superadmin', wrap(async (req, res) => {
  const { username, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM super_admins WHERE username=$1', [username]);
  const row = rows[0];
  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ token: signToken({ role: 'superadmin', id: row.id }) });
}));

app.post('/api/login/admin', wrap(async (req, res) => {
  const { school_id, username, password } = req.body;
  const schoolRes = await pool.query('SELECT * FROM schools WHERE id=$1', [school_id]);
  if (!schoolRes.rows[0] || schoolRes.rows[0].active === false) {
    return res.status(403).json({ error: 'This school is not active. Contact the system administrator.' });
  }
  const { rows } = await pool.query('SELECT * FROM admins WHERE school_id=$1 AND username=$2', [school_id, username]);
  const row = rows[0];
  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ token: signToken({ role: 'admin', id: row.id, school_id: row.school_id }) });
}));

app.post('/api/login/teacher', wrap(async (req, res) => {
  const { school_id, serial_number, password } = req.body;
  const schoolRes = await pool.query('SELECT * FROM schools WHERE id=$1', [school_id]);
  if (!schoolRes.rows[0] || schoolRes.rows[0].active === false) {
    return res.status(403).json({ error: 'This school is not active. Contact the system administrator.' });
  }
  const { rows } = await pool.query(
    'SELECT * FROM teachers WHERE school_id=$1 AND serial_number=$2 AND active=TRUE',
    [school_id, serial_number]
  );
  const row = rows[0];
  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({
    token: signToken({ role: 'teacher', id: row.id, school_id: row.school_id }),
    must_reset_password: row.must_reset_password
  });
}));

app.post('/api/teacher/reset-password', requireRole('teacher'), wrap(async (req, res) => {
  const { new_password } = req.body;
  const hash = bcrypt.hashSync(new_password, 10);
  await pool.query('UPDATE teachers SET password_hash=$1, must_reset_password=FALSE WHERE id=$2', [hash, req.user.id]);
  res.json({ ok: true });
}));

// ---------- SUPER ADMIN: schools ----------
app.post('/api/schools', requireRole('superadmin'), wrap(async (req, res) => {
  const { name, admin_username, admin_password } = req.body;
  const { rows } = await pool.query('INSERT INTO schools (name) VALUES ($1) RETURNING id', [name]);
  const schoolId = rows[0].id;
  const hash = bcrypt.hashSync(admin_password, 10);
  await pool.query('INSERT INTO admins (school_id, username, password_hash) VALUES ($1,$2,$3)', [schoolId, admin_username, hash]);
  res.json({ school_id: schoolId });
}));

app.get('/api/schools', requireRole('superadmin'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM schools ORDER BY id');
  res.json(rows);
}));

app.patch('/api/schools/:id/active', requireRole('superadmin'), wrap(async (req, res) => {
  const { active } = req.body;
  await pool.query('UPDATE schools SET active=$1 WHERE id=$2', [!!active, req.params.id]);
  res.json({ ok: true });
}));

app.delete('/api/schools/:id', requireRole('superadmin'), wrap(async (req, res) => {
  try {
    await pool.query('DELETE FROM schools WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '23503') {
      return res.status(400).json({ error: 'Cannot delete: this school already has classes, learners, or other data. Deactivate it instead.' });
    }
    throw err;
  }
}));

// ---------- ADMIN: classes ----------
app.post('/api/classes', requireRole('admin'), wrap(async (req, res) => {
  const { grade, stream_name } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO classes (school_id, grade, stream_name) VALUES ($1,$2,$3) RETURNING id',
    [req.user.school_id, grade, stream_name]
  );
  res.json({ id: rows[0].id });
}));

app.get('/api/classes', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM classes WHERE school_id=$1 ORDER BY grade, stream_name', [req.user.school_id]);
  res.json(rows);
}));

app.patch('/api/classes/:id', requireRole('admin'), wrap(async (req, res) => {
  const { grade, stream_name } = req.body;
  await pool.query(
    'UPDATE classes SET grade=$1, stream_name=$2 WHERE id=$3 AND school_id=$4',
    [grade, stream_name, req.params.id, req.user.school_id]
  );
  res.json({ ok: true });
}));

// ---------- ADMIN: learners ----------
app.post('/api/learners', requireRole('admin'), wrap(async (req, res) => {
  const { class_id, upi_number, name, sex, admission_number, assessment_number } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO learners (school_id, class_id, upi_number, name, sex, admission_number, assessment_number)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
    [req.user.school_id, class_id, upi_number, name, sex, admission_number, assessment_number]
  );
  res.json({ id: rows[0].id });
}));

app.get('/api/classes/:classId/list', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM learners WHERE school_id=$1 AND class_id=$2 ORDER BY name',
    [req.user.school_id, req.params.classId]
  );
  res.json(rows);
}));

app.delete('/api/learners/:id', requireRole('admin'), wrap(async (req, res) => {
  await pool.query('DELETE FROM learners WHERE id=$1 AND school_id=$2', [req.params.id, req.user.school_id]);
  res.json({ ok: true });
}));

app.patch('/api/learners/:id', requireRole('admin'), wrap(async (req, res) => {
  const { name, sex, upi_number, admission_number, assessment_number } = req.body;
  await pool.query(
    `UPDATE learners SET name=$1, sex=$2, upi_number=$3, admission_number=$4, assessment_number=$5
     WHERE id=$6 AND school_id=$7`,
    [name, sex, upi_number, admission_number, assessment_number, req.params.id, req.user.school_id]
  );
  res.json({ ok: true });
}));

// ---------- ADMIN: subjects ----------
app.post('/api/subjects', requireRole('admin'), wrap(async (req, res) => {
  const { grade, name } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO subjects (school_id, grade, name) VALUES ($1,$2,$3) RETURNING id',
    [req.user.school_id, grade, name]
  );
  res.json({ id: rows[0].id });
}));

app.get('/api/subjects', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  const { grade } = req.query;
  const { rows } = grade
    ? await pool.query('SELECT * FROM subjects WHERE school_id=$1 AND grade=$2', [req.user.school_id, grade])
    : await pool.query('SELECT * FROM subjects WHERE school_id=$1', [req.user.school_id]);
  res.json(rows);
}));

app.delete('/api/subjects/:id', requireRole('admin'), wrap(async (req, res) => {
  await pool.query('DELETE FROM subjects WHERE id=$1 AND school_id=$2', [req.params.id, req.user.school_id]);
  res.json({ ok: true });
}));

app.patch('/api/subjects/:id', requireRole('admin'), wrap(async (req, res) => {
  const { grade, name } = req.body;
  await pool.query(
    'UPDATE subjects SET grade=$1, name=$2 WHERE id=$3 AND school_id=$4',
    [grade, name, req.params.id, req.user.school_id]
  );
  res.json({ ok: true });
}));

// ---------- ADMIN: teachers ----------
app.post('/api/teachers', requireRole('admin'), wrap(async (req, res) => {
  const { serial_number, full_name } = req.body;
  const firstName = full_name.trim().split(' ')[0].toLowerCase();
  const hash = bcrypt.hashSync(firstName, 10);
  const { rows } = await pool.query(
    `INSERT INTO teachers (school_id, serial_number, full_name, password_hash, must_reset_password, active)
     VALUES ($1,$2,$3,$4,TRUE,TRUE) RETURNING id`,
    [req.user.school_id, serial_number, full_name, hash]
  );
  res.json({ id: rows[0].id, username: serial_number, temp_password: firstName });
}));

app.get('/api/teachers', requireRole('admin'), wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, serial_number, full_name, active FROM teachers WHERE school_id=$1',
    [req.user.school_id]
  );
  res.json(rows);
}));

app.patch('/api/teachers/:id/active', requireRole('admin'), wrap(async (req, res) => {
  const { active } = req.body;
  await pool.query('UPDATE teachers SET active=$1 WHERE id=$2 AND school_id=$3', [!!active, req.params.id, req.user.school_id]);
  res.json({ ok: true });
}));

app.post('/api/teacher-assignments', requireRole('admin'), wrap(async (req, res) => {
  const { teacher_id, class_id, subject_id } = req.body;
  await pool.query(
    `INSERT INTO teacher_assignments (school_id, teacher_id, class_id, subject_id)
     VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
    [req.user.school_id, teacher_id, class_id, subject_id]
  );
  res.json({ ok: true });
}));

app.get('/api/teacher-assignments', requireRole('admin'), wrap(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT ta.*, t.full_name as teacher_name, s.name as subject_name, c.stream_name, c.grade
    FROM teacher_assignments ta
    JOIN teachers t ON t.id = ta.teacher_id
    JOIN subjects s ON s.id = ta.subject_id
    JOIN classes c ON c.id = ta.class_id
    WHERE ta.school_id = $1
  `, [req.user.school_id]);
  res.json(rows);
}));

app.delete('/api/teacher-assignments/:id', requireRole('admin'), wrap(async (req, res) => {
  await pool.query('DELETE FROM teacher_assignments WHERE id=$1 AND school_id=$2', [req.params.id, req.user.school_id]);
  res.json({ ok: true });
}));

app.get('/api/teacher-assignments/mine', requireRole('teacher'), wrap(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT ta.*, s.name as subject_name, c.stream_name, c.grade
    FROM teacher_assignments ta
    JOIN subjects s ON s.id = ta.subject_id
    JOIN classes c ON c.id = ta.class_id
    WHERE ta.teacher_id = $1 AND ta.school_id = $2
  `, [req.user.id, req.user.school_id]);
  res.json(rows);
}));

// ---------- ADMIN: exam sessions ----------
app.post('/api/exam-sessions', requireRole('admin'), wrap(async (req, res) => {
  const { name } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO exam_sessions (school_id, name, is_open) VALUES ($1,$2,FALSE) RETURNING id',
    [req.user.school_id, name]
  );
  res.json({ id: rows[0].id });
}));

app.patch('/api/exam-sessions/:id/toggle', requireRole('admin'), wrap(async (req, res) => {
  const { is_open } = req.body;
  await pool.query('UPDATE exam_sessions SET is_open=$1 WHERE id=$2 AND school_id=$3', [!!is_open, req.params.id, req.user.school_id]);
  res.json({ ok: true });
}));

app.get('/api/exam-sessions', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM exam_sessions WHERE school_id=$1 ORDER BY id', [req.user.school_id]);
  res.json(rows);
}));

// ---------- TEACHER: enter marks ----------
app.post('/api/marks', requireRole('teacher'), wrap(async (req, res) => {
  const { exam_session_id, learner_id, subject_id, score } = req.body;

  if (score === undefined || score === null || Number(score) < 1 || Number(score) > 99) {
    return res.status(400).json({ error: 'Score must be between 01 and 99.' });
  }

  const sessionRes = await pool.query('SELECT * FROM exam_sessions WHERE id=$1 AND school_id=$2', [exam_session_id, req.user.school_id]);
  const session = sessionRes.rows[0];
  if (!session || !session.is_open) {
    return res.status(403).json({ error: 'This exam session is closed. Ask the admin to open it.' });
  }

  const learnerRes = await pool.query('SELECT * FROM learners WHERE id=$1 AND school_id=$2', [learner_id, req.user.school_id]);
  const learner = learnerRes.rows[0];

  const assignedRes = await pool.query(
    'SELECT * FROM teacher_assignments WHERE teacher_id=$1 AND class_id=$2 AND subject_id=$3 AND school_id=$4',
    [req.user.id, learner.class_id, subject_id, req.user.school_id]
  );
  if (!assignedRes.rows[0]) {
    return res.status(403).json({ error: 'You are not assigned to teach this subject for this class.' });
  }

  await pool.query(`
    INSERT INTO marks (school_id, exam_session_id, learner_id, subject_id, teacher_id, score)
    VALUES ($1,$2,$3,$4,$5,$6)
    ON CONFLICT (exam_session_id, learner_id, subject_id)
    DO UPDATE SET score=EXCLUDED.score, teacher_id=EXCLUDED.teacher_id, entered_at=NOW()
  `, [req.user.school_id, exam_session_id, learner_id, subject_id, req.user.id, score]);

  res.json({ ok: true });
}));

app.put('/api/marks/admin-override', requireRole('admin'), wrap(async (req, res) => {
  const { exam_session_id, learner_id, subject_id, score } = req.body;
  if (score === undefined || score === null || Number(score) < 1 || Number(score) > 99) {
    return res.status(400).json({ error: 'Score must be between 01 and 99.' });
  }
  await pool.query(`
    INSERT INTO marks (school_id, exam_session_id, learner_id, subject_id, teacher_id, score)
    VALUES ($1,$2,$3,$4, 0, $5)
    ON CONFLICT (exam_session_id, learner_id, subject_id)
    DO UPDATE SET score=EXCLUDED.score, entered_at=NOW()
  `, [req.user.school_id, exam_session_id, learner_id, subject_id, score]);
  res.json({ ok: true });
}));

// ---------- MARK SHEET ----------
app.get('/api/marksheet/:classId/:examSessionId', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  const { classId, examSessionId } = req.params;
  const learnersRes = await pool.query('SELECT * FROM learners WHERE school_id=$1 AND class_id=$2 ORDER BY name', [req.user.school_id, classId]);
  const clsRes = await pool.query('SELECT * FROM classes WHERE id=$1', [classId]);
  const cls = clsRes.rows[0];
  const subjectsRes = await pool.query('SELECT * FROM subjects WHERE school_id=$1 AND grade=$2', [req.user.school_id, cls.grade]);
  const marksRes = await pool.query(
    `SELECT * FROM marks WHERE school_id=$1 AND exam_session_id=$2 AND learner_id IN (SELECT id FROM learners WHERE class_id=$3)`,
    [req.user.school_id, examSessionId, classId]
  );

  const marksByLearner = {};
  for (const m of marksRes.rows) {
    marksByLearner[m.learner_id] = marksByLearner[m.learner_id] || {};
    marksByLearner[m.learner_id][m.subject_id] = m.score;
  }

  res.json({
    class: cls,
    subjects: subjectsRes.rows,
    rows: learnersRes.rows.map(l => ({
      learner: l,
      scores: subjectsRes.rows.map(s => marksByLearner[l.id]?.[s.id] ?? null)
    }))
  });
}));

// ---------- GRADING BANDS ----------
app.post('/api/grading-bands', requireRole('admin'), wrap(async (req, res) => {
  const { min_score, max_score, grade_letter, points } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO grading_bands (school_id, min_score, max_score, grade_letter, points) VALUES ($1,$2,$3,$4,$5) RETURNING id',
    [req.user.school_id, min_score, max_score, grade_letter, points]
  );
  res.json({ id: rows[0].id });
}));

app.get('/api/grading-bands', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM grading_bands WHERE school_id=$1 ORDER BY min_score DESC', [req.user.school_id]);
  res.json(rows);
}));

app.delete('/api/grading-bands/:id', requireRole('admin'), wrap(async (req, res) => {
  await pool.query('DELETE FROM grading_bands WHERE id=$1 AND school_id=$2', [req.params.id, req.user.school_id]);
  res.json({ ok: true });
}));

async function scoreToBand(schoolId, score) {
  const { rows } = await pool.query('SELECT * FROM grading_bands WHERE school_id=$1', [schoolId]);
  return rows.find(b => score >= b.min_score && score <= b.max_score) || null;
}

// ---------- ANALYTICS ----------
app.get('/api/analysis/:examSessionId/grade/:grade', requireRole('admin'), wrap(async (req, res) => {
  const { examSessionId, grade } = req.params;
  const learnersRes = await pool.query(`
    SELECT l.* FROM learners l JOIN classes c ON c.id = l.class_id
    WHERE l.school_id=$1 AND c.grade=$2
  `, [req.user.school_id, grade]);

  const results = [];
  for (const l of learnersRes.rows) {
    const marksRes = await pool.query('SELECT score FROM marks WHERE exam_session_id=$1 AND learner_id=$2', [examSessionId, l.id]);
    const marks = marksRes.rows;
    const total = marks.reduce((a, m) => a + Number(m.score), 0);
    const mean = marks.length ? total / marks.length : 0;
    results.push({ learner: l, total, mean, subjects_recorded: marks.length });
  }
  results.sort((a, b) => b.mean - a.mean);
  const learnerRanking = results.map((r, i) => ({ position: i + 1, ...r }));

  const subjectsRes = await pool.query('SELECT * FROM subjects WHERE school_id=$1 AND grade=$2', [req.user.school_id, grade]);
  const subjectRanking = [];
  for (const s of subjectsRes.rows) {
    const marksRes = await pool.query(`
      SELECT m.score FROM marks m JOIN learners l ON l.id = m.learner_id
      WHERE m.exam_session_id=$1 AND m.subject_id=$2 AND l.class_id IN (
        SELECT id FROM classes WHERE school_id=$3 AND grade=$4
      )
    `, [examSessionId, s.id, req.user.school_id, grade]);
    const marks = marksRes.rows;
    const mean = marks.length ? marks.reduce((a, m) => a + Number(m.score), 0) / marks.length : 0;
    subjectRanking.push({ subject: s.name, mean, entries: marks.length });
  }
  subjectRanking.sort((a, b) => b.mean - a.mean);

  res.json({ learnerRanking, subjectRanking });
}));

app.get('/api/analysis/class/:classId/:examSessionId', requireRole('admin'), wrap(async (req, res) => {
  const { classId, examSessionId } = req.params;

  const clsRes = await pool.query('SELECT * FROM classes WHERE id=$1 AND school_id=$2', [classId, req.user.school_id]);
  const cls = clsRes.rows[0];
  if (!cls) return res.status(404).json({ error: 'Class not found' });

  const subjectsRes = await pool.query('SELECT * FROM subjects WHERE school_id=$1 AND grade=$2 ORDER BY name', [req.user.school_id, cls.grade]);
  const subjects = subjectsRes.rows;

  const learnersRes = await pool.query('SELECT * FROM learners WHERE school_id=$1 AND class_id=$2 ORDER BY name', [req.user.school_id, classId]);
  const learners = learnersRes.rows;

  const marksRes = await pool.query(
    'SELECT * FROM marks WHERE exam_session_id=$1 AND learner_id IN (SELECT id FROM learners WHERE class_id=$2)',
    [examSessionId, classId]
  );
  const marks = marksRes.rows;

  const marksByLearner = {};
  marks.forEach(m => {
    marksByLearner[m.learner_id] = marksByLearner[m.learner_id] || {};
    marksByLearner[m.learner_id][m.subject_id] = Number(m.score);
  });

  const learnerRanking = learners.map(l => {
    const subjectScores = subjects.map(s => ({
      subject: s.name,
      score: marksByLearner[l.id] && marksByLearner[l.id][s.id] !== undefined ? marksByLearner[l.id][s.id] : null
    }));
    const recorded = subjectScores.filter(s => s.score !== null).map(s => s.score);
    const mean = recorded.length ? recorded.reduce((a, b) => a + b, 0) / recorded.length : 0;
    return { learner: l, mean, subjects: subjectScores };
  }).sort((a, b) => b.mean - a.mean)
    .map((r, i) => ({ position: i + 1, ...r }));

  const subjectRanking = subjects.map(s => {
    const scores = learners
      .map(l => (marksByLearner[l.id] ? marksByLearner[l.id][s.id] : undefined))
      .filter(v => v !== undefined);
    const mean = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
    return { subject: s.name, mean, entries: scores.length };
  }).sort((a, b) => b.mean - a.mean);

  const prevRes = await pool.query(
    'SELECT * FROM exam_sessions WHERE school_id=$1 AND id < $2 ORDER BY id DESC LIMIT 1',
    [req.user.school_id, examSessionId]
  );
  const prevExam = prevRes.rows[0] || null;

  let mostImproved = [];
  let classTrend = null;

  if (prevExam) {
    const prevMarksRes = await pool.query(
      'SELECT * FROM marks WHERE exam_session_id=$1 AND learner_id IN (SELECT id FROM learners WHERE class_id=$2)',
      [prevExam.id, classId]
    );
    const prevMarksByLearner = {};
    prevMarksRes.rows.forEach(m => {
      prevMarksByLearner[m.learner_id] = prevMarksByLearner[m.learner_id] || [];
      prevMarksByLearner[m.learner_id].push(Number(m.score));
    });

    mostImproved = learners.map(l => {
      const currentScores = marksByLearner[l.id] ? Object.values(marksByLearner[l.id]) : [];
      const currentMean = currentScores.length ? currentScores.reduce((a, b) => a + b, 0) / currentScores.length : null;
      const prevScoresArr = prevMarksByLearner[l.id] || [];
      const prevMean = prevScoresArr.length ? prevScoresArr.reduce((a, b) => a + b, 0) / prevScoresArr.length : null;
      if (currentMean === null || prevMean === null) return null;
      return { learner: l, previousMean: prevMean, currentMean, improvement: currentMean - prevMean };
    }).filter(x => x !== null)
      .sort((a, b) => b.improvement - a.improvement);

    const currentAll = marks.map(m => Number(m.score));
    const currentClassMean = currentAll.length ? currentAll.reduce((a, b) => a + b, 0) / currentAll.length : 0;
    const prevAll = prevMarksRes.rows.map(m => Number(m.score));
    const prevClassMean = prevAll.length ? prevAll.reduce((a, b) => a + b, 0) / prevAll.length : 0;

    classTrend = {
      previousExamName: prevExam.name,
      previousMean: prevClassMean,
      currentMean: currentClassMean,
      change: currentClassMean - prevClassMean
    };
  }

  res.json({ class: cls, learnerRanking, subjectRanking, mostImproved, classTrend });
}));

// ---------- INDIVIDUAL REPORT ----------
app.get('/api/report/:learnerId/:examSessionId', requireRole('admin'), wrap(async (req, res) => {
  const { learnerId, examSessionId } = req.params;
  const learnerRes = await pool.query('SELECT * FROM learners WHERE id=$1 AND school_id=$2', [learnerId, req.user.school_id]);
  const learner = learnerRes.rows[0];

  const marksRes = await pool.query(`
    SELECT m.*, s.name as subject_name FROM marks m JOIN subjects s ON s.id = m.subject_id
    WHERE m.exam_session_id=$1 AND m.learner_id=$2
  `, [examSessionId, learnerId]);

  const withGrades = [];
  for (const m of marksRes.rows) {
    withGrades.push({ ...m, band: await scoreToBand(req.user.school_id, m.score) });
  }

  const classmatesRes = await pool.query('SELECT id FROM learners WHERE class_id=$1', [learner.class_id]);
  const totals = [];
  for (const c of classmatesRes.rows) {
    const cmRes = await pool.query('SELECT score FROM marks WHERE exam_session_id=$1 AND learner_id=$2', [examSessionId, c.id]);
    const cm = cmRes.rows;
    totals.push({ id: c.id, mean: cm.length ? cm.reduce((a, m) => a + Number(m.score), 0) / cm.length : 0 });
  }
  totals.sort((a, b) => b.mean - a.mean);
  const position = totals.findIndex(t => t.id == learnerId) + 1;

  const historyRes = await pool.query(`
    SELECT es.name as exam_name, es.id as exam_session_id, AVG(m.score) as average
    FROM marks m JOIN exam_sessions es ON es.id = m.exam_session_id
    WHERE m.learner_id=$1 GROUP BY es.id, es.name ORDER BY es.id
  `, [learnerId]);

  const remarkRes = await pool.query('SELECT * FROM report_remarks WHERE learner_id=$1 AND exam_session_id=$2', [learnerId, examSessionId]);

  res.json({
    learner,
    marks: withGrades,
    position,
    totalInClass: classmatesRes.rows.length,
    history: historyRes.rows,
    remark: remarkRes.rows[0] || {}
  });
}));

app.post('/api/report/:learnerId/:examSessionId/remarks', requireRole('admin'), wrap(async (req, res) => {
  const { learnerId, examSessionId } = req.params;
  const { class_teacher_remark, head_teacher_remark } = req.body;
  await pool.query(`
    INSERT INTO report_remarks (school_id, learner_id, exam_session_id, class_teacher_remark, head_teacher_remark)
    VALUES ($1,$2,$3,$4,$5)
  `, [req.user.school_id, learnerId, examSessionId, class_teacher_remark, head_teacher_remark]);
  res.json({ ok: true });
}));

app.get('/api/school', requireRole('admin'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM schools WHERE id=$1', [req.user.school_id]);
  res.json(rows[0]);
}));

app.post('/api/timetable', requireRole('admin'), wrap(async (req, res) => {
  const { class_id, day_of_week, period_number, subject_id, teacher_id } = req.body;
  await pool.query(
    'DELETE FROM timetable_entries WHERE school_id=$1 AND class_id=$2 AND day_of_week=$3 AND period_number=$4',
    [req.user.school_id, class_id, day_of_week, period_number]
  );
  await pool.query(
    `INSERT INTO timetable_entries (school_id, class_id, day_of_week, period_number, subject_id, teacher_id)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [req.user.school_id, class_id, day_of_week, period_number, subject_id, teacher_id]
  );
  res.json({ ok: true });
}));

app.get('/api/timetable/:classId', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT te.*, s.name as subject_name, t.full_name as teacher_name
    FROM timetable_entries te
    LEFT JOIN subjects s ON s.id = te.subject_id
    LEFT JOIN teachers t ON t.id = te.teacher_id
    WHERE te.school_id=$1 AND te.class_id=$2
  `, [req.user.school_id, req.params.classId]);
  res.json(rows);
}));

app.delete('/api/timetable/:id', requireRole('admin'), wrap(async (req, res) => {
  await pool.query('DELETE FROM timetable_entries WHERE id=$1 AND school_id=$2', [req.params.id, req.user.school_id]);
  res.json({ ok: true });
}));

// ---------- School profile ----------
app.get('/api/school-settings', requireRole('admin'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM school_settings WHERE school_id=$1', [req.user.school_id]);
  if (!rows[0]) {
    return res.json({
      school_id: req.user.school_id,
      day_start_time: '08:00',
      lessons_per_day: 8,
      break1_after_period: 2,
      break1_duration: 15,
      break2_after_period: 5,
      break2_duration: 15,
      lunch_after_period_primary: 4,
      lunch_after_period_junior: 5,
      lunch_duration: 40
    });
  }
  res.json(rows[0]);
}));

app.post('/api/school-settings', requireRole('admin'), wrap(async (req, res) => {
  const {
    day_start_time, lessons_per_day,
    break1_after_period, break1_duration,
    break2_after_period, break2_duration,
    lunch_after_period_primary, lunch_after_period_junior, lunch_duration
  } = req.body;
  await pool.query(`
    INSERT INTO school_settings (school_id, day_start_time, lessons_per_day, break1_after_period, break1_duration,
      break2_after_period, break2_duration, lunch_after_period_primary, lunch_after_period_junior, lunch_duration)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    ON CONFLICT (school_id) DO UPDATE SET
      day_start_time=EXCLUDED.day_start_time, lessons_per_day=EXCLUDED.lessons_per_day,
      break1_after_period=EXCLUDED.break1_after_period, break1_duration=EXCLUDED.break1_duration,
      break2_after_period=EXCLUDED.break2_after_period, break2_duration=EXCLUDED.break2_duration,
      lunch_after_period_primary=EXCLUDED.lunch_after_period_primary,
      lunch_after_period_junior=EXCLUDED.lunch_after_period_junior,
      lunch_duration=EXCLUDED.lunch_duration
  `, [req.user.school_id, day_start_time, lessons_per_day, break1_after_period, break1_duration,
      break2_after_period, break2_duration, lunch_after_period_primary, lunch_after_period_junior, lunch_duration]);
  res.json({ ok: true });
}));

app.post('/api/subject-lessons', requireRole('admin'), wrap(async (req, res) => {
  const { grade, subject_id, lessons_per_week } = req.body;
  await pool.query(`
    INSERT INTO subject_lessons_per_week (school_id, grade, subject_id, lessons_per_week)
    VALUES ($1,$2,$3,$4)
    ON CONFLICT (school_id, grade, subject_id) DO UPDATE SET lessons_per_week=EXCLUDED.lessons_per_week
  `, [req.user.school_id, grade, subject_id, lessons_per_week]);
  res.json({ ok: true });
}));

app.get('/api/subject-lessons', requireRole('admin'), wrap(async (req, res) => {
  const { grade } = req.query;
  const { rows } = grade
    ? await pool.query('SELECT * FROM subject_lessons_per_week WHERE school_id=$1 AND grade=$2', [req.user.school_id, grade])
    : await pool.query('SELECT * FROM subject_lessons_per_week WHERE school_id=$1', [req.user.school_id]);
  res.json(rows);
}));

app.post('/api/timetable/generate', requireRole('admin'), wrap(async (req, res) => {
  const schoolId = req.user.school_id;

  const settingsRes = await pool.query('SELECT * FROM school_settings WHERE school_id=$1', [schoolId]);
  const settings = settingsRes.rows[0] || { lessons_per_day: 8 };
  const lessonsPerDay = settings.lessons_per_day || 8;
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];

  const classesRes = await pool.query('SELECT * FROM classes WHERE school_id=$1', [schoolId]);
  const classes = classesRes.rows;

  const assignRes = await pool.query('SELECT * FROM teacher_assignments WHERE school_id=$1', [schoolId]);
  const assignments = assignRes.rows;

  const lpwRes = await pool.query('SELECT * FROM subject_lessons_per_week WHERE school_id=$1', [schoolId]);
  const lpwMap = {};
  lpwRes.rows.forEach(r => { lpwMap[`${r.grade}-${r.subject_id}`] = r.lessons_per_week; });

  const requirements = [];
  for (const a of assignments) {
    const cls = classes.find(c => c.id === a.class_id);
    if (!cls) continue;
    const count = lpwMap[`${cls.grade}-${a.subject_id}`];
    if (!count) continue;
    requirements.push({ class_id: a.class_id, subject_id: a.subject_id, teacher_id: a.teacher_id, count });
  }

  requirements.sort((x, y) => y.count - x.count);

  function shuffle(arr) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  const classBusy = {};
  const teacherBusy = {};
  const classDaySubject = {};
  const placements = [];
  const unplaced = [];

  for (const requirement of requirements) {
    let placedCount = 0;
    for (let pass = 0; pass < 2 && placedCount < requirement.count; pass++) {
      const shuffledDays = shuffle(days);
      for (const day of shuffledDays) {
        if (placedCount >= requirement.count) break;
        const daySubjectKey = `${requirement.class_id}-${day}-${requirement.subject_id}`;
        if (pass === 0 && classDaySubject[daySubjectKey]) continue;
        const shuffledPeriods = shuffle(Array.from({ length: lessonsPerDay }, (_, i) => i + 1));
        for (const period of shuffledPeriods) {
          if (placedCount >= requirement.count) break;
          const classKey = `${requirement.class_id}-${day}-${period}`;
          const teacherKey = `${requirement.teacher_id}-${day}-${period}`;
          if (classBusy[classKey] || teacherBusy[teacherKey]) continue;
          classBusy[classKey] = true;
          teacherBusy[teacherKey] = true;
          classDaySubject[daySubjectKey] = (classDaySubject[daySubjectKey] || 0) + 1;
          placements.push({
            class_id: requirement.class_id, subject_id: requirement.subject_id,
            teacher_id: requirement.teacher_id, day_of_week: day, period_number: period
          });
          placedCount++;
        }
      }
    }
    if (placedCount < requirement.count) {
      unplaced.push({
        class_id: requirement.class_id, subject_id: requirement.subject_id,
        teacher_id: requirement.teacher_id, missing: requirement.count - placedCount
      });
    }
  }

  await pool.query('DELETE FROM timetable_entries WHERE school_id=$1', [schoolId]);
  for (const p of placements) {
    await pool.query(
      `INSERT INTO timetable_entries (school_id, class_id, day_of_week, period_number, subject_id, teacher_id)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [schoolId, p.class_id, p.day_of_week, p.period_number, p.subject_id, p.teacher_id]
    );
  }

  res.json({
    placed: placements.length,
    total_requested: requirements.reduce((a, r) => a + r.count, 0),
    unplaced
  });
}));

app.get('/api/timetable/teacher/:teacherId', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT te.*, s.name as subject_name, c.stream_name, c.grade
    FROM timetable_entries te
    LEFT JOIN subjects s ON s.id = te.subject_id
    JOIN classes c ON c.id = te.class_id
    WHERE te.school_id=$1 AND te.teacher_id=$2
  `, [req.user.school_id, req.params.teacherId]);
  res.json(rows);
}));

app.patch('/api/school/name', requireRole('admin'), wrap(async (req, res) => {
  await pool.query('UPDATE schools SET name=$1 WHERE id=$2', [req.body.name, req.user.school_id]);
  res.json({ ok: true });
}));

app.get('/api/session-check', requireRole('admin', 'teacher'), wrap(async (req, res) => {
  res.json({ ok: true });
}));

app.get('/api/health', (req, res) => res.json({ ok: true }));

module.exports = app;

// Only start a local server when run directly (e.g. `node server.js`).
// On Vercel, api/index.js imports `app` instead and Vercel handles the listening.
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => console.log(`SIS backend running on http://localhost:${PORT}`));
}