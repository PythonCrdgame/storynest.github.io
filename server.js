// server.js - Node.js backend with Express, MongoDB Atlas, and JWT Authentication
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRE = '7d';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Atlas connection
const MONGODB_URI = process.env.MONGODB_URI || 'your-backup-connection-string';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  process.exit(1);
});

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: 6,
    select: false // Don't include password in queries by default
  },
  fullName: {
    type: String,
    trim: true
  },
  avatar: {
    type: String,
    default: '📚'
  },
  readingLevel: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced'],
    default: 'beginner'
  },
  favoriteGenres: [{
    type: String
  }],
  booksRead: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date
  }
});

// Book Schema
const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, required: true },
  age: { type: String, default: 'All ages' },
  genre: { type: String },
  description: { type: String },
  coverIcon: { type: String, default: '📖' },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  createdAt: { type: Date, default: Date.now },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  reads: { type: Number, default: 0 }
});

// Reading Progress Schema
const readingProgressSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  book: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Book',
    required: true
  },
  currentPage: { type: Number, default: 0 },
  totalPages: { type: Number, default: 100 },
  completed: { type: Boolean, default: false },
  lastRead: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);
const ReadingProgress = mongoose.model('ReadingProgress', readingProgressSchema);

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access denied. Please login.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Generate JWT Token
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
};

// ===== AUTH ROUTES =====

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ 
        error: existingUser.email === email ? 'Email already registered' : 'Username already taken' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      fullName: fullName || username
    });

    await user.save();

    // Generate token
    const token = generateToken(user._id);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: 'lax'
    });

    res.status(201).json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Error creating account' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user and include password
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateToken(user._id);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'lax'
    });

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        avatar: user.avatar,
        readingLevel: user.readingLevel,
        booksRead: user.booksRead
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error logging in' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: 'Logged out successfully' });
});

// GET /api/auth/me - Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  res.json({ user: req.user });
});

// ===== BOOK ROUTES (Protected) =====

// GET /api/books - Get all books (public)
app.get('/api/books', async (req, res) => {
  try {
    const books = await Book.find()
      .sort({ createdAt: -1 })
      .populate('createdBy', 'username avatar');
    res.json(books);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch books' });
  }
});

// POST /api/books - Add new book (authenticated)
app.post('/api/books', authenticateToken, async (req, res) => {
  try {
    const { title, author, age, genre, description } = req.body;
    
    if (!title || !author) {
      return res.status(400).json({ error: 'Title and author are required' });
    }

    const book = new Book({
      title,
      author,
      age: age || 'All ages',
      genre,
      description,
      createdBy: req.user._id
    });

    const saved = await book.save();
    await saved.populate('createdBy', 'username avatar');
    
    res.status(201).json(saved);
  } catch (err) {
    res.status(500).json({ error: 'Could not create book' });
  }
});

// POST /api/books/:id/like - Like a book
app.post('/api/books/:id/like', authenticateToken, async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    
    if (!book) {
      return res.status(404).json({ error: 'Book not found' });
    }

    const likeIndex = book.likes.indexOf(req.user._id);
    
    if (likeIndex > -1) {
      book.likes.splice(likeIndex, 1); // Unlike
    } else {
      book.likes.push(req.user._id); // Like
    }

    await book.save();
    res.json({ likes: book.likes.length, isLiked: likeIndex === -1 });
  } catch (err) {
    res.status(500).json({ error: 'Error updating like' });
  }
});

// ===== READING PROGRESS ROUTES =====

// POST /api/progress - Update reading progress
app.post('/api/progress', authenticateToken, async (req, res) => {
  try {
    const { bookId, currentPage, totalPages } = req.body;
    
    let progress = await ReadingProgress.findOne({
      user: req.user._id,
      book: bookId
    });

    if (progress) {
      progress.currentPage = currentPage;
      progress.totalPages = totalPages || progress.totalPages;
      progress.completed = currentPage >= progress.totalPages;
      progress.lastRead = new Date();
    } else {
      progress = new ReadingProgress({
        user: req.user._id,
        book: bookId,
        currentPage,
        totalPages: totalPages || 100
      });
    }

    await progress.save();
    
    // Update user's books read count
    if (progress.completed) {
      await User.findByIdAndUpdate(req.user._id, { $inc: { booksRead: 1 } });
    }

    res.json(progress);
  } catch (err) {
    res.status(500).json({ error: 'Error updating progress' });
  }
});

// GET /api/progress - Get user's reading progress
app.get('/api/progress', authenticateToken, async (req, res) => {
  try {
    const progress = await ReadingProgress.find({ user: req.user._id })
      .populate('book', 'title author coverIcon');
    res.json(progress);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching progress' });
  }
});

// Serve HTML pages
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 StoryNest server running on http://localhost:${PORT}`);
});
