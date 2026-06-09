require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(helmet());
app.use(cors());
app.use(express.json());

// General rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please try again later.' }
});
app.use(limiter);

// Stricter limiter for login routes (brute force protection)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many login attempts. Please try again after 15 minutes.' }
});

/* ================= DB CONNECTION ================= */
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

/* ================= MODELS ================= */

// Admin
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

// Officer
const officerSchema = new mongoose.Schema({
  name:    { type: String, required: true, trim: true },
  address: { type: String, required: true, trim: true },
  mobile: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: v => /^\d{10}$/.test(v),
      message: props => `${props.value} is not a valid 10-digit mobile number`
    }
  },
  username:  { type: String, required: true, unique: true, trim: true },
  password:  { type: String, required: true },
  subscribed: { type: Boolean, default: false },
  transactionId: {
    type: String,
    unique: true,
    sparse: true,
    validate: {
      validator: v => !v || /^\d{12}$/.test(v),
      message: 'Transaction ID must be exactly 12 digits'
    }
  },
  subscriptionDate: Date,
  createdAt: { type: Date, default: Date.now }
});
const Officer = mongoose.models.Officer || mongoose.model('Officer', officerSchema);

// Result
const resultSchema = new mongoose.Schema({
  username: String,
  name:     String,
  address:  String,
  score:    Number,
  total:    Number,
  date:     { type: Date, default: Date.now }
});
const Result = mongoose.models.Result || mongoose.model('Result', resultSchema);

// Transfer Application
const transferSchema = new mongoose.Schema({
  username:        { type: String, required: true },
  transferType:    { type: String, enum: ['One Way', 'Mutual'], required: true },
  applicantName:   { type: String, required: true },
  workingDistrict: { type: String, required: true },
  designation: {
    type: String,
    enum: ["SRI", "JRI", "TYPIST", "STENO TYPIST", "DEPUTY TAHSILDAR", "TAHSILDAR"],
    required: true
  },
  dateOfJoining: { type: Date, required: true },
  option1:       { type: String, required: true },
  option2:       String,
  option3:       String,
  contactNumber: { type: String, required: true },
  createdAt:     { type: Date, default: Date.now }
});
const TransferApplication =
  mongoose.models.TransferApplication ||
  mongoose.model('TransferApplication', transferSchema);

/* ================= CONSTANTS ================= */
const ALLOWED_DESIGNATIONS = [
  "SRI", "JRI", "TYPIST", "STENO TYPIST", "DEPUTY TAHSILDAR", "TAHSILDAR"
];

// Secret code for admin password reset — set in .env as ADMIN_RESET_SECRET
const ADMIN_RESET_SECRET = process.env.ADMIN_RESET_SECRET || 'TNGovt@Reset2025';

/* ================= HELPERS ================= */

// Async error wrapper — avoids try/catch repeat in every route
const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// Validate mobile
function isValidMobile(m) { return /^\d{10}$/.test(m); }

// Validate username
function isValidUsername(u) { return /^[a-zA-Z0-9_]{4,20}$/.test(u); }

// Validate transaction ID
function isValidTxnId(t) { return /^\d{12}$/.test(t); }

/* ================= INIT ADMIN ================= */
async function initializeAdmin() {
  try {
    const exists = await Admin.exists({ username: 'admin' });
    if (!exists) {
      const hash = await bcrypt.hash('admin123', 10);
      await Admin.create({ username: 'admin', password: hash });
      console.log('✅ Default admin created (username: admin, password: admin123)');
    }
  } catch (err) {
    console.error('Admin init error:', err);
  }
}
initializeAdmin();

/* ================= ROUTES ================= */

// Health check
app.get('/', (req, res) => res.json({ status: 'TN Govt Servant Portal API running ✅' }));

/* ---------- AUTH ROUTES ---------- */

// Admin Login
app.post('/admin/login', loginLimiter, asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required.' });

  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password)))
    return res.status(401).json({ error: 'Invalid credentials.' });

  res.json({ message: 'Admin login successful' });
}));

// Admin Reset Password (with secret code)
app.post('/admin/reset-password', asyncHandler(async (req, res) => {
  const { secretCode, password } = req.body;

  if (!secretCode || !password)
    return res.status(400).json({ error: 'Secret code and new password required.' });

  if (secretCode !== ADMIN_RESET_SECRET)
    return res.status(403).json({ error: 'Invalid secret code.' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const hash = await bcrypt.hash(password, 10);
  await Admin.updateOne({ username: 'admin' }, { password: hash });
  res.json({ message: 'Admin password reset successfully.' });
}));

// Officer Login
app.post('/login', loginLimiter, asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required.' });

  const officer = await Officer.findOne({ username });
  if (!officer || !(await bcrypt.compare(password, officer.password)))
    return res.status(401).json({ error: 'Invalid credentials.' });

  const obj = officer.toObject();
  delete obj.password;
  res.json({ message: 'Login successful', officer: obj, subscribed: officer.subscribed });
}));

// Officer Signup
app.post('/signup', asyncHandler(async (req, res) => {
  const { name, address, mobile, username, password } = req.body;

  // Validations
  if (!name || !address || !mobile || !username || !password)
    return res.status(400).json({ error: 'All fields are required.' });

  if (!isValidMobile(mobile))
    return res.status(400).json({ error: 'Mobile must be exactly 10 digits.' });

  if (!isValidUsername(username))
    return res.status(400).json({ error: 'Username: 4-20 chars, letters/numbers/underscore only.' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  // Check duplicates
  const existingUser = await Officer.findOne({
    $or: [{ username }, { mobile }]
  });
  if (existingUser) {
    if (existingUser.username === username)
      return res.status(409).json({ error: 'Username already taken.' });
    if (existingUser.mobile === mobile)
      return res.status(409).json({ error: 'Mobile number already registered.' });
  }

  const hash = await bcrypt.hash(password, 10);
  const officer = await Officer.create({ name, address, mobile, username, password: hash });
  const obj = officer.toObject();
  delete obj.password;
  res.json({ message: 'Officer registered successfully.', officer: obj });
}));

// Officer Reset Password
app.post('/officer/reset-password', asyncHandler(async (req, res) => {
  const { username, mobile, password } = req.body;

  if (!username || !mobile || !password)
    return res.status(400).json({ error: 'All fields required.' });

  if (!isValidMobile(mobile))
    return res.status(400).json({ error: 'Invalid mobile number.' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const officer = await Officer.findOne({ username, mobile });
  if (!officer)
    return res.status(404).json({ error: 'No officer found with this username and mobile.' });

  officer.password = await bcrypt.hash(password, 10);
  await officer.save();
  res.json({ message: 'Password reset successfully.' });
}));

/* ---------- SUBSCRIPTION ROUTES ---------- */

// Submit Transaction ID
app.post('/submit-transaction', asyncHandler(async (req, res) => {
  const { username, transactionId } = req.body;

  if (!username || !transactionId)
    return res.status(400).json({ error: 'Username and Transaction ID required.' });

  if (!isValidTxnId(transactionId))
    return res.status(400).json({ error: 'Transaction ID must be exactly 12 digits.' });

  // Check if txnId already used by another officer
  const existing = await Officer.findOne({ transactionId });
  if (existing && existing.username !== username)
    return res.status(409).json({ error: 'This Transaction ID is already registered.' });

  const officer = await Officer.findOneAndUpdate(
    { username },
    { transactionId, subscribed: false },
    { new: true }
  );
  if (!officer)
    return res.status(404).json({ error: 'Officer not found.' });

  res.json({ message: 'Transaction ID submitted successfully. Awaiting admin approval.' });
}));

// Officer Status
app.post('/officer/status', asyncHandler(async (req, res) => {
  const officer = await Officer.findOne({ username: req.body.username });
  if (!officer) return res.status(404).json({ error: 'Officer not found.' });
  res.json({ activated: officer.subscribed });
}));

/* ---------- ADMIN ROUTES ---------- */

// Get all officers (no password)
app.get('/admin/officers', asyncHandler(async (req, res) => {
  const officers = await Officer.find({}, { password: 0 }).sort({ createdAt: -1 });
  res.json(officers);
}));

// Activate subscription
app.post('/admin/activate', asyncHandler(async (req, res) => {
  const { transactionId } = req.body;

  if (!isValidTxnId(transactionId))
    return res.status(400).json({ error: 'Transaction ID must be 12 digits.' });

  const officer = await Officer.findOne({ transactionId });
  if (!officer)
    return res.status(404).json({ error: 'No officer found with this Transaction ID.' });

  if (officer.subscribed)
    return res.status(409).json({ error: 'This officer is already activated.' });

  officer.subscribed = true;
  officer.subscriptionDate = new Date();
  await officer.save();
  res.json({ message: `Subscription activated for ${officer.name} (${officer.username}).` });
}));

/* ─────────────────────────────────────────
   NEW: Edit Officer (name, address, mobile)
───────────────────────────────────────── */
app.post('/admin/officer/update', asyncHandler(async (req, res) => {
  const { username, name, address, mobile } = req.body;

  if (!username)
    return res.status(400).json({ error: 'Username required to identify officer.' });

  if (!name || name.trim().length === 0)
    return res.status(400).json({ error: 'Name cannot be empty.' });

  if (!isValidMobile(mobile))
    return res.status(400).json({ error: 'Mobile must be exactly 10 digits.' });

  // Check mobile conflict with another officer
  const conflict = await Officer.findOne({ mobile, username: { $ne: username } });
  if (conflict)
    return res.status(409).json({ error: 'This mobile number is used by another officer.' });

  const officer = await Officer.findOneAndUpdate(
    { username },
    { name: name.trim(), address: (address || '').trim(), mobile },
    { new: true, runValidators: true }
  );

  if (!officer)
    return res.status(404).json({ error: 'Officer not found.' });

  const obj = officer.toObject();
  delete obj.password;
  res.json({ message: 'Officer details updated successfully.', officer: obj });
}));

/* ─────────────────────────────────────────
   NEW: Delete Officer
───────────────────────────────────────── */
app.post('/admin/officer/delete', asyncHandler(async (req, res) => {
  const { username } = req.body;

  if (!username)
    return res.status(400).json({ error: 'Username required.' });

  const officer = await Officer.findOneAndDelete({ username });
  if (!officer)
    return res.status(404).json({ error: 'Officer not found.' });

  res.json({ message: `Officer "${username}" deleted successfully.` });
}));

/* ---------- RESULT ROUTES ---------- */

// Submit Result
app.post('/submit-result', asyncHandler(async (req, res) => {
  const { username, name, address, score, total } = req.body;
  if (!username || score === undefined || total === undefined)
    return res.status(400).json({ error: 'username, score, and total are required.' });
  await Result.create({ username, name, address, score, total });
  res.json({ message: 'Result submitted successfully.' });
}));

// Get Results
app.get('/get-results', asyncHandler(async (req, res) => {
  const list = await Result.find().sort({ date: -1 });
  res.json(list);
}));

/* ---------- TRANSFER ROUTES ---------- */

// Apply Transfer
app.post('/transfer/apply', asyncHandler(async (req, res) => {
  const designation = req.body.designation?.trim().toUpperCase();
  if (!ALLOWED_DESIGNATIONS.includes(designation))
    return res.status(400).json({ error: `Invalid designation. Allowed: ${ALLOWED_DESIGNATIONS.join(', ')}` });

  const required = ['username', 'transferType', 'applicantName', 'workingDistrict', 'dateOfJoining', 'option1', 'contactNumber'];
  for (const field of required) {
    if (!req.body[field])
      return res.status(400).json({ error: `${field} is required.` });
  }

  const application = await TransferApplication.create({ ...req.body, designation });
  res.json({ message: 'Transfer application submitted successfully.', id: application._id });
}));

// Transfer list helpers
const transferList = designation => asyncHandler(async (req, res) => {
  const filter = designation ? { designation } : {};
  const apps = await TransferApplication.find(filter).sort({ createdAt: -1 });
  res.json(apps);
});

app.get('/transfer/all',              transferList(null));
app.get('/transfer/sri',              transferList('SRI'));
app.get('/transfer/jri',              transferList('JRI'));
app.get('/transfer/typist',           transferList('TYPIST'));
app.get('/transfer/stenotypist',      transferList('STENO TYPIST'));
app.get('/transfer/deputytahsildar',  transferList('DEPUTY TAHSILDAR'));
app.get('/transfer/tahsildar',        transferList('TAHSILDAR'));

/* ================= GLOBAL ERROR HANDLER ================= */
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.message);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(e => e.message).join(', ');
    return res.status(400).json({ error: messages });
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || 'field';
    const value = err.keyValue?.[field];
    return res.status(409).json({ error: `"${value}" is already registered for ${field}.` });
  }

  res.status(500).json({ error: 'Internal server error. Please try again.' });
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
