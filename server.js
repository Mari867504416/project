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
  mobile: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  subscribed: { type: Boolean, default: false },
  transactionId: { type: String, default: '' },
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
    
    res.json({ 
      message: 'Login successful',
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
    
    res.json({ message: 'Officer created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit Transaction ID
app.post('/submit-transaction', async (req, res) => {
  try {
    const { transactionId } = req.body;
    const { username } = req.query; // You might want to send username in headers or body
    
    const officer = await Officer.findOneAndUpdate(
      { username },
      { transactionId },
      { new: true }
    );
    
    if (!officer) {
      return res.status(404).json({ error: 'Officer not found' });
    }
    
    res.json({ message: 'Transaction ID submitted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
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
    
    const officer = await Officer.findOneAndUpdate(
      { transactionId },
      { subscribed: true, transactionId: '' },
      { new: true }
    );
    
    if (!officer) {
      return res.status(404).json({ message: 'No officer found with this transaction ID' });
    }
    
    res.json({ message: 'Subscription activated successfully' });
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