require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const Admin = mongoose.model('Admin', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}));

const Officer = mongoose.model('Officer', new mongoose.Schema({
  name: { type: String, required: true },
  address: { type: String, required: true },
  mobile: { 
    type: String, 
    required: true, 
    unique: true,
    validate: {
      validator: function(v) {
        return /^\d{10}$/.test(v);
      },
      message: props => `${props.value} is not a valid 10-digit mobile number!`
    }
  },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  subscribed: { type: Boolean, default: false },
  transactionId: { 
    type: String,
    validate: {
      validator: function(v) {
        return !v || /^\d{12}$/.test(v);
      },
      message: props => `${props.value} is not a valid 12-digit transaction ID!`
    },
    unique: true,
    sparse: true
  },
  subscriptionDate: { type: Date },
  createdAt: { type: Date, default: Date.now }
}));

// Initialize Admin
async function initializeAdmin() {
  const adminExists = await Admin.exists({ username: 'admin' });
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await Admin.create({ username: 'admin', password: hashedPassword });
    console.log('Default admin created');
  }
}

// Routes

// Admin Login
app.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    res.json({ message: 'Admin login successful' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Officer Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const officer = await Officer.findOne({ username });
    
    if (!officer) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, officer.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const officerData = officer.toObject();
    delete officerData.password;
    
    res.json({ 
      message: 'Login successful',
      officer: officerData,
      subscribed: officer.subscribed
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Officer Signup
app.post('/signup', async (req, res) => {
  try {
    const { name, address, mobile, username, password } = req.body;
    
    if (!/^\d{10}$/.test(mobile)) {
      return res.status(400).json({ error: 'Invalid mobile number' });
    }
    
    const existingOfficer = await Officer.findOne({ $or: [{ username }, { mobile }] });
    if (existingOfficer) {
      return res.status(400).json({ error: 'Username or mobile number already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newOfficer = await Officer.create({
      name,
      address,
      mobile,
      username,
      password: hashedPassword
    });
    
    const officerData = newOfficer.toObject();
    delete officerData.password;
    
    res.json({ 
      message: 'Officer created successfully',
      officer: officerData
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit Transaction ID
const transactionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many transaction submissions, please try again later'
});

app.post('/submit-transaction', transactionLimiter, async (req, res) => {
  try {
    const { transactionId, username } = req.body;
    
    if (!transactionId || !username) {
      return res.status(400).json({ error: 'Transaction ID and username are required' });
    }
    
    if (!/^\d{12}$/.test(transactionId)) {
      return res.status(400).json({ error: 'Transaction ID must be exactly 12 digits' });
    }
    
    // Check if transaction ID already exists
    const existingTransaction = await Officer.findOne({ transactionId });
    if (existingTransaction) {
      return res.status(400).json({ error: 'This transaction ID has already been used' });
    }
    
    const updatedOfficer = await Officer.findOneAndUpdate(
      { username },
      { 
        transactionId,
        subscriptionDate: new Date(),
        subscribed: false // Ensure subscribed is false until admin activates
      },
      { new: true }
    );
    
    if (!updatedOfficer) {
      return res.status(404).json({ error: 'Officer not found' });
    }
    
    res.json({ 
      message: 'Transaction submitted successfully',
      transactionId: updatedOfficer.transactionId
    });
    
  } catch (error) {
    console.error('Transaction submission error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin - Get all officers
app.get('/admin/officers', async (req, res) => {
  try {
    const officers = await Officer.find({}, { password: 0 })
      .sort({ createdAt: -1 }); // Sort by newest first
    res.json(officers);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin - Activate subscription
app.post('/admin/activate', async (req, res) => {
  try {
    const { transactionId } = req.body;
    console.log("Received transactionId:", transactionId);

    // Validate format (12-digit number)
    if (!transactionId || !/^\d{12}$/.test(transactionId)) {
      return res.status(400).json({ error: 'Invalid or missing 12-digit transaction ID' });
    }

    // Find the officer by transactionId
    const officer = await Officer.findOne({ transactionId });
    if (!officer) {
      return res.status(404).json({ error: 'No officer found with this transaction ID' });
    }
    console.log("Officer found:", officer.username);

    if (officer.subscribed) {
      return res.status(400).json({ error: 'Officer is already subscribed' });
    }

    // Activate the officer (keep transactionId to avoid unique null conflicts)
    officer.subscribed = true;
    officer.subscriptionDate = new Date();

    await officer.save();
    console.log("Officer activated successfully:", officer.username);

    res.json({ message: 'Subscription activated successfully' });
  } catch (error) {
    console.error('Activation error:', error);
    res.status(500).json({ error: 'Internal server error during activation' });
  }
});




// Admin - Reset password
app.post('/admin/reset-password', async (req, res) => {
  try {
    const { password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await Admin.findOneAndUpdate(
      { username: 'admin' },
      { password: hashedPassword }
    );
    
    res.json({ message: 'Admin password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize admin on startup
initializeAdmin();

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
app.post('/officer/status', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const officer = await Officer.findOne({ username });

    if (!officer) {
      return res.status(404).json({ error: 'Officer not found' });
    }

    res.json({ activated: officer.subscribed });
  } catch (error) {
    console.error('Error checking activation status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Officer - Reset password via username and mobile number
app.post('/officer/reset-password', async (req, res) => {
  try {
    const { username, mobile, password } = req.body;

    if (!username || !mobile || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const officer = await Officer.findOne({ username, mobile });

    if (!officer) {
      return res.status(404).json({ error: 'Officer not found or mobile number does not match' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    officer.password = hashedPassword;
    await officer.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Officer password reset error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const Result = mongoose.model('Result', new mongoose.Schema({
  username: { type: String, required: true },
  name: { type: String, required: true },
  address: { type: String },
  score: { type: Number, required: true },
  total: { type: Number, required: true },
  date: { type: Date, default: Date.now }
}));
app.post('/submit-result', async (req, res) => {
  try {
    const { username, name, phone, score, total, date } = req.body;

    if (!username || score == null || total == null) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const newResult = new Result({
      username,
      name: name || "Unknown",
      phone: phone || "Not Provided",
      score,
      total,
      date: date ? new Date(date) : new Date()
    });

    await newResult.save();
    res.json({ message: 'Result submitted successfully' });
  } catch (error) {
    console.error('Submit result error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/get-results', async (req, res) => {
  try {
    const results = await Result.find().sort({ date: -1 });
    res.json(results);
  } catch (error) {
    console.error('Fetch results error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Transfer Application
const TransferApplication =
  mongoose.models.TransferApplication ||
  mongoose.model('TransferApplication', new mongoose.Schema({
    username: { type: String, required: true },

    transferType: {
      type: String,
      enum: ['One Way', 'Mutual'],
      required: true
    },

    applicantName: { type: String, required: true },
    workingDistrict: { type: String, required: true },

    designation: {
      type: String,
      enum: ["SRI", "JRI", "TYPIST", "STENO TYPIST"], // ✅ FIX
      required: true
    },

    dateOfJoining: { type: Date, required: true },

    option1: { type: String, required: true },
    option2: String,
    option3: String,

    contactNumber: { type: String, required: true },

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
/* ================= CONSTANTS ================= */
const ALLOWED_DESIGNATIONS = [
  "SRI",
  "JRI",
  "TYPIST",
  "STENO TYPIST"
];
/* -------- Apply Transfer (FIXED) -------- */
app.post('/transfer/apply', async (req, res) => {
  try {
    const officer = await Officer.findOne({ username: req.body.username });
    if (!officer) {
      return res.status(404).json({ error: 'Officer not found' });
    }

    const requiredFields = [
      "username",
      "applicantName",
      "workingDistrict",
      "designation",
      "dateOfJoining",
      "option1",
      "contactNumber"
    ];

    for (let field of requiredFields) {
      if (!req.body[field]) {
        return res.status(400).json({ error: `${field} is required` });
      }
    }

    /* ✅ DESIGNATION NORMALIZE */
    const designation = req.body.designation
      .toString()
      .trim()
      .toUpperCase();

    if (!ALLOWED_DESIGNATIONS.includes(designation)) {
      return res.status(400).json({
        error: "Invalid designation"
      });
    }

    const application = await TransferApplication.create({
      ...req.body,
      designation // ✅ clean value only
    });

    res.json({
      message: 'Transfer application submitted successfully',
      id: application._id
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});


/* -------- Dashboard / Get all Transfers -------- */
app.get('/transfer/all', async (req, res) => {
  try {
    const list = await TransferApplication
      .find({}, { __v: 0 })
      .sort({ createdAt: -1 });

    res.json(list);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});
app.get('/transfer/sri', async (req, res) => {
  const list = await TransferApplication.find({ designation: "SRI" });
  res.json(list);
});
app.get('/transfer/jri', async (req, res) => {
  const list = await TransferApplication.find({ designation: "JRI" });
  res.json(list);
});
app.get('/transfer/typist', async (req, res) => {
  const list = await TransferApplication.find({ designation: "TYPIST" });
  res.json(list);
});
app.get('/transfer/stenotypist', async (req, res) => {
  const list = await TransferApplication.find({ designation: "STENO TYPIST" });
  res.json(list);
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
