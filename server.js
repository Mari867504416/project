require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// Constants
const ADMIN_INITIAL_PASSWORD = process.env.ADMIN_INITIAL_PASSWORD || 'admin123';
const SALT_ROUNDS = 10;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 100;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX_REQUESTS
});
app.use(limiter);

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000
    });
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

// Models
const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  lastPasswordReset: { type: Date, default: Date.now }
});

const OfficerSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  address: { type: String, required: true, trim: true },
  mobile: { 
    type: String, 
    required: true, 
    unique: true,
    validate: {
      validator: function(v) {
        return /^\d{10}$/.test(v);
      },
      message: props => `${props.value} is not a valid mobile number!`
    }
  },
  username: { 
    type: String, 
    required: true, 
    unique: true,
    minlength: 4,
    maxlength: 20
  },
  password: { type: String, required: true },
  subscribed: { type: Boolean, default: false },
  transactionId: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

// Add indexes
OfficerSchema.index({ username: 1 });
OfficerSchema.index({ mobile: 1 });

const Admin = mongoose.model('Admin', AdminSchema);
const Officer = mongoose.model('Officer', OfficerSchema);

// Initialize Admin (run once)
async function initializeAdmin() {
  try {
    const adminExists = await Admin.exists({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(ADMIN_INITIAL_PASSWORD, SALT_ROUNDS);
      await Admin.create({ 
        username: 'admin', 
        password: hashedPassword 
      });
      console.log('Default admin created');
      console.warn(`IMPORTANT: Change the default admin password (current: ${ADMIN_INITIAL_PASSWORD})`);
    }
  } catch (error) {
    console.error('Error initializing admin:', error);
  }
}

// Utility functions
const handleServerError = (res, error, customMessage = 'Server error') => {
  console.error(error);
  return res.status(500).json({ 
    error: customMessage,
    details: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
};

// Routes

// Admin Login
app.post('/admin/login', [
  body('username').trim().notEmpty(),
  body('password').trim().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

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
    
    // Update last login time
    await Admin.updateOne({ _id: admin._id }, { lastLogin: Date.now() });
    
    res.json({ 
      message: 'Admin login successful',
      lastPasswordReset: admin.lastPasswordReset
    });
  } catch (error) {
    handleServerError(res, error);
  }
});

// Officer Login
app.post('/login', [
  body('username').trim().notEmpty(),
  body('password').trim().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

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
    
    // Update last login time
    await Officer.updateOne({ _id: officer._id }, { lastLogin: Date.now() });
    
    res.json({ 
      message: 'Login successful',
      subscribed: officer.subscribed,
      name: officer.name
    });
  } catch (error) {
    handleServerError(res, error);
  }
});

// Officer Signup
app.post('/signup', [
  body('name').trim().notEmpty().isLength({ min: 3 }),
  body('address').trim().notEmpty(),
  body('mobile').trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('username').trim().isLength({ min: 4, max: 20 }),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { name, address, mobile, username, password } = req.body;
    
    const existingOfficer = await Officer.findOne({ $or: [{ username }, { mobile }] });
    if (existingOfficer) {
      return res.status(400).json({ 
        error: existingOfficer.username === username 
          ? 'Username already exists' 
          : 'Mobile number already registered'
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const newOfficer = await Officer.create({
      name,
      address,
      mobile,
      username,
      password: hashedPassword
    });
    
    res.status(201).json({ 
      message: 'Officer created successfully',
      id: newOfficer._id
    });
  } catch (error) {
    handleServerError(res, error, 'Registration failed');
  }
});

// Submit Transaction ID
app.post('/submit-transaction', [
  body('transactionId').trim().notEmpty(),
  body('username').trim().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { transactionId, username } = req.body;
    
    const officer = await Officer.findOneAndUpdate(
      { username },
      { transactionId },
      { new: true }
    );
    
    if (!officer) {
      return res.status(404).json({ error: 'Officer not found' });
    }
    
    res.json({ 
      message: 'Transaction ID submitted successfully',
      transactionId: officer.transactionId
    });
  } catch (error) {
    handleServerError(res, error);
  }
});

// Admin - Get all officers
app.get('/admin/officers', async (req, res) => {
  try {
    const officers = await Officer.find({}, { password: 0 })
      .sort({ createdAt: -1 });
    res.json(officers);
  } catch (error) {
    handleServerError(res, error);
  }
});

// Admin - Activate subscription
app.post('/admin/activate', [
  body('transactionId').trim().notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { transactionId } = req.body;
    
    const officer = await Officer.findOneAndUpdate(
      { transactionId },
      { subscribed: true, transactionId: '' },
      { new: true }
    );
    
    if (!officer) {
      return res.status(404).json({ message: 'No officer found with this transaction ID' });
    }
    
    res.json({ 
      message: 'Subscription activated successfully',
      officer: {
        name: officer.name,
        username: officer.username,
        subscribed: officer.subscribed
      }
    });
  } catch (error) {
    handleServerError(res, error);
  }
});

// Admin - Reset password
app.post('/admin/reset-password', [
  body('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { password } = req.body;
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    await Admin.findOneAndUpdate(
      { username: 'admin' },
      { 
        password: hashedPassword,
        lastPasswordReset: Date.now()
      }
    );
    
    res.json({ message: 'Admin password updated successfully' });
  } catch (error) {
    handleServerError(res, error);
  }
});

// Start server
const startServer = async () => {
  try {
    await connectDB();
    await initializeAdmin();
    
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();