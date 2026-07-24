const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

function signToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: '12h' });
}

function requireRole(...roles) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'No token provided' });
    const token = header.replace('Bearer ', '');
    try {
      const decoded = jwt.verify(token, SECRET);
      if (!roles.includes(decoded.role)) {
        return res.status(403).json({ error: 'Not authorized for this action' });
      }
      req.user = decoded;
      next();
    } catch (e) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}

module.exports = { signToken, requireRole, SECRET };