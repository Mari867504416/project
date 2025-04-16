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
        // Only validate if there's a value and not empty string
        return !v || /^\d{12}$/.test(v);
      },
      message: props => `${props.value} is not a valid 12-digit transaction ID!`
    },
    unique: true,
    sparse: true // Allows multiple null values but enforces uniqueness for non-null
  },
  subscriptionDate: { type: Date },
  createdAt: { type: Date, default: Date.now }
}));

// Initialize Admin (run once)
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
    
    // Return officer data (excluding password)
    const officerData = officer.toObject();
    delete officerData.password;
    
    res.json({ 
      message: 'Login successful',
      officer: officerData
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Officer Signup
app.post('/signup', async (req, res) => {
  try {
    const { name, address, mobile, username, password } = req.body;
    
    // Validate mobile number
    if (!/^\d{10}$/.test(mobile)) {
      return res.status(400).json({ error: 'Invalid mobile number' });
    }
    
    // Check if username or mobile already exists
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
    
    // Return officer data without password
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

// Submit Transaction ID (12-digit only)
const rateLimit = require('express-rate-limit');

// Strict rate limiting for transaction submissions
const transactionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 attempts per window
  message: 'Too many transaction submissions, please try again later'
});

app.post('/submit-transaction', transactionLimiter, async (req, res) => {
  try {
    const { transactionId, username } = req.body;
    
    // Validate presence
    if (!transactionId || !username) {
      return res.status(400).json({ error: 'Transaction ID and username are required' });
    }
    
    // Strict 12-digit number validation
    if (!/^\d{12}$/.test(transactionId)) {
      return res.status(400).json({ error: 'Transaction ID must be exactly 12 digits' });
    }
    
    // Update officer record
    const updatedOfficer = await Officer.findOneAndUpdate(
      { username },
      { 
        transactionId,
        subscriptionDate: new Date(),
        subscriptionStatus: 'pending' 
      },
      { new: true }
    );
    
    if (!updatedOfficer) {
      return res.status(404).json({ error: 'Officer not found' });
    }
    
    return res.json({ 
      message: 'Transaction submitted successfully',
      transactionId: updatedOfficer.transactionId
    });
    
  } catch (error) {
    console.error('Transaction submission error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin - Get all officers
app.get('/admin/officers', async (req, res) => {
  try {
    const officers = await Officer.find({}, { password: 0 });
    res.json(officers);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin - Activate subscription
app.post('/admin/activate', async (req, res) => {
  try {
    const { transactionId } = req.body;
    
    // Validate transaction ID format
    if (!/^\d{12}$/.test(transactionId)) {
      return res.status(400).json({ message: 'Invalid transaction ID format' });
    }
    
    // Find officer by transaction ID
    const officer = await Officer.findOne({ transactionId });
    if (!officer) {
      return res.status(404).json({ message: 'No officer found with this transaction ID' });
    }
    
    // Check if already subscribed
    if (officer.subscribed) {
      return res.status(400).json({ message: 'Officer is already subscribed' });
    }
    
    // Update subscription status
    const updatedOfficer = await Officer.findOneAndUpdate(
      { transactionId },
      { 
        subscribed: true,
        transactionId: '', // Clear transaction ID after activation
        subscriptionDate: new Date() 
      },
      { new: true }
    );
    
    // Return updated officer data without password
    const officerData = updatedOfficer.toObject();
    delete officerData.password;
    
    res.json({ 
      message: 'Subscription activated successfully',
      officer: officerData
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
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
