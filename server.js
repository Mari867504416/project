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

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

/* ================= DB CONNECTION ================= */
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

/* ================= MODELS ================= */

// Admin
const Admin = mongoose.models.Admin || mongoose.model('Admin', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}));

// Officer
const Officer = mongoose.models.Officer || mongoose.model('Officer', new mongoose.Schema({
  name: String,
  address: String,
  mobile: { type: String, unique: true },
  username: { type: String, unique: true },
  password: String,
  subscribed: { type: Boolean, default: false },
  transactionId: { type: String, unique: true, sparse: true },
  subscriptionDate: Date,
  createdAt: { type: Date, default: Date.now }
}));

// Result
const Result = mongoose.models.Result || mongoose.model('Result', new mongoose.Schema({
  username: String,
  name: String,
  address: String,
  score: Number,
  total: Number,
  date: { type: Date, default: Date.now }
}));

// Transfer Application
const TransferApplication =
  mongoose.models.TransferApplication ||
  mongoose.model('TransferApplication', new mongoose.Schema({
    username: { type: String, required: true },

    transferType: {
      type: String,
      enum: ['One Way', 'Mutual'],   // ✅ FIXED ENUM
      required: true
    },

    applicantName: { type: String, required: true },
    workingDistrict: { type: String, required: true },
    designation: { type: String, required: true },
    dateOfJoining: { type: Date, required: true },

    option1: { type: String, required: true },
    option2: String,
    option3: String,

    createdAt: { type: Date, default: Date.now }
  }));

/* ================= INIT ADMIN ================= */
async function initializeAdmin() {
  const exists = await Admin.exists({ username: 'admin' });
  if (!exists) {
    const hash = await bcrypt.hash('admin123', 10);
    await Admin.create({ username: 'admin', password: hash });
    console.log('Default admin created');
  }
}
initializeAdmin();

/* ================= ROUTES ================= */

/* -------- Admin Login -------- */
app.post('/admin/login', async (req, res) => {
  const admin = await Admin.findOne({ username: req.body.username });
  if (!admin || !(await bcrypt.compare(req.body.password, admin.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ message: 'Admin login successful' });
});

/* -------- Officer Login -------- */
app.post('/login', async (req, res) => {
  const officer = await Officer.findOne({ username: req.body.username });
  if (!officer || !(await bcrypt.compare(req.body.password, officer.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const obj = officer.toObject();
  delete obj.password;
  res.json({ message: 'Login successful', officer: obj, subscribed: officer.subscribed });
});

/* -------- Officer Signup -------- */
app.post('/signup', async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  const officer = await Officer.create({ ...req.body, password: hash });
  const obj = officer.toObject();
  delete obj.password;
  res.json({ message: 'Officer created successfully', officer: obj });
});

/* -------- Transaction Submit -------- */
app.post('/submit-transaction', async (req, res) => {
  const officer = await Officer.findOneAndUpdate(
    { username: req.body.username },
    { transactionId: req.body.transactionId, subscribed: false },
    { new: true }
  );
  if (!officer) return res.status(404).json({ error: 'Officer not found' });
  res.json({ message: 'Transaction submitted successfully' });
});

/* -------- Admin Activate -------- */
app.post('/admin/activate', async (req, res) => {
  const officer = await Officer.findOne({ transactionId: req.body.transactionId });
  if (!officer) return res.status(404).json({ error: 'Not found' });
  officer.subscribed = true;
  officer.subscriptionDate = new Date();
  await officer.save();
  res.json({ message: 'Subscription activated successfully' });
});

/* -------- Officer Status -------- */
app.post('/officer/status', async (req, res) => {
  const officer = await Officer.findOne({ username: req.body.username });
  if (!officer) return res.status(404).json({ error: 'Officer not found' });
  res.json({ activated: officer.subscribed });
});

/* -------- Officer Reset Password -------- */
app.post('/officer/reset-password', async (req, res) => {
  const officer = await Officer.findOne({ username: req.body.username, mobile: req.body.mobile });
  if (!officer) return res.status(404).json({ error: 'Officer not found' });
  officer.password = await bcrypt.hash(req.body.password, 10);
  await officer.save();
  res.json({ message: 'Password reset successfully' });
});

/* -------- Submit Result -------- */
app.post('/submit-result', async (req, res) => {
  await Result.create(req.body);
  res.json({ message: 'Result submitted successfully' });
});

/* -------- Get Results -------- */
app.get('/get-results', async (req, res) => {
  const list = await Result.find().sort({ date: -1 });
  res.json(list);
});

/* ================= TRANSFER MODULE ================= */

/* -------- Apply Transfer -------- */
app.post('/transfer/apply', async (req, res) => {
  try {
    const officer = await Officer.findOne({ username: req.body.username });
    if (!officer) return res.status(404).json({ error: 'Officer not found' });
    if (!officer.subscribed) return res.status(403).json({ error: 'Subscription not active' });

    await TransferApplication.create(req.body);
    res.json({ message: 'Transfer application submitted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

/* -------- Dashboard -------- */
app.get('/transfer/all', async (req, res) => {
  const list = await TransferApplication.find({}, { __v: 0 }).sort({ createdAt: -1 });
  res.json(list);
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
