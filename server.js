require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-12345';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// ==================== SCHEMAS ====================

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  fullName: String,
  avatar: { type: String, default: '👤' },
  bio: { type: String, default: 'Book lover 📚' },
  readingGoal: { type: Number, default: 20 },
  booksRead: { type: Number, default: 0 },
  joinedDate: { type: Date, default: Date.now },
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Book' }]
});

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, required: true },
  description: { type: String, default: 'A wonderful book waiting to be explored.' },
  age: { type: String, default: 'All ages' },
  genre: { type: String, default: 'Fiction' },
  coverIcon: { type: String, default: '📖' },
  pages: { type: Number, default: 100 },
  rating: { type: Number, default: 0 },
  totalRatings: { type: Number, default: 0 },
  reads: { type: Number, default: 0 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  reviews: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    rating: Number,
    date: { type: Date, default: Date.now }
  }]
});

const readingProgressSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  book: { type: mongoose.Schema.Types.ObjectId, ref: 'Book', required: true },
  currentPage: { type: Number, default: 0 },
  completed: { type: Boolean, default: false },
  startedAt: { type: Date, default: Date.now },
  lastRead: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);
const ReadingProgress = mongoose.model('ReadingProgress', readingProgressSchema);

// ==================== AUTH MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Please login' });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.userId);
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ==================== AUTH ROUTES ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', mongodb: mongoose.connection.readyState === 1 });
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const avatars = ['👤', '🦊', '🐱', '🐶', '🦄', '🐼', '🐨', '🐯'];
    
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      fullName: fullName || username,
      avatar: avatars[Math.floor(Math.random() * avatars.length)]
    });
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      token,
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
    res.status(500).json({ error: 'Server error during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        avatar: user.avatar,
        bio: user.bio,
        readingGoal: user.readingGoal,
        booksRead: user.booksRead
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const user = await User.findById(req.user._id).populate('favorites');
  res.json({ user });
});

app.put('/api/auth/profile', auth, async (req, res) => {
  try {
    const { fullName, bio, readingGoal } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { fullName, bio, readingGoal },
      { new: true }
    );
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ==================== BOOK ROUTES ====================

app.get('/api/books', async (req, res) => {
  try {
    const { genre, search, sort } = req.query;
    let query = {};
    if (genre && genre !== 'All') query.genre = genre;
    if (search) query.title = { $regex: search, $options: 'i' };
    
    let sortOption = { createdAt: -1 };
    if (sort === 'rating') sortOption = { rating: -1 };
    if (sort === 'popular') sortOption = { reads: -1 };
    if (sort === 'title') sortOption = { title: 1 };
    
    const books = await Book.find(query).sort(sortOption).populate('createdBy', 'username');
    res.json(books);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching books' });
  }
});

app.get('/api/books/:id', async (req, res) => {
  try {
    const book = await Book.findById(req.params.id)
      .populate('createdBy', 'username avatar')
      .populate('reviews.user', 'username avatar');
    if (!book) return res.status(404).json({ error: 'Book not found' });
    res.json(book);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching book' });
  }
});

app.post('/api/books', auth, async (req, res) => {
  try {
    const { title, author, description, age, genre, pages } = req.body;
    if (!title || !author) return res.status(400).json({ error: 'Title and author required' });
    
    const icons = ['📖', '📚', '📕', '📗', '📘', '📙', '🌟', '🔥', '💡', '🎯', '🎨', '🎭'];
    
    const book = await Book.create({
      title, author,
      description: description || 'A wonderful book waiting to be explored.',
      age: age || 'All ages',
      genre: genre || 'Fiction',
      pages: pages || 100,
      coverIcon: icons[Math.floor(Math.random() * icons.length)],
      createdBy: req.user._id
    });
    
    res.status(201).json(book);
  } catch (error) {
    res.status(500).json({ error: 'Error adding book' });
  }
});

app.post('/api/books/:id/review', auth, async (req, res) => {
  try {
    const { text, rating } = req.body;
    const book = await Book.findById(req.params.id);
    if (!book) return res.status(404).json({ error: 'Book not found' });
    
    book.reviews.push({ user: req.user._id, text, rating });
    book.totalRatings += 1;
    book.rating = book.reviews.reduce((acc, r) => acc + r.rating, 0) / book.reviews.length;
    await book.save();
    
    res.json(book);
  } catch (error) {
    res.status(500).json({ error: 'Error adding review' });
  }
});

app.post('/api/books/:id/favorite', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const bookId = req.params.id;
    const index = user.favorites.indexOf(bookId);
    
    if (index > -1) {
      user.favorites.splice(index, 1);
    } else {
      user.favorites.push(bookId);
    }
    
    await user.save();
    res.json({ favorites: user.favorites, isFavorited: index === -1 });
  } catch (error) {
    res.status(500).json({ error: 'Error updating favorites' });
  }
});

// ==================== READING PROGRESS ====================

app.post('/api/progress', auth, async (req, res) => {
  try {
    const { bookId, currentPage } = req.body;
    let progress = await ReadingProgress.findOne({ user: req.user._id, book: bookId });
    const book = await Book.findById(bookId);
    
    if (progress) {
      progress.currentPage = currentPage;
      progress.lastRead = new Date();
      if (currentPage >= book.pages) {
        if (!progress.completed) {
          progress.completed = true;
          await User.findByIdAndUpdate(req.user._id, { $inc: { booksRead: 1 } });
          await Book.findByIdAndUpdate(bookId, { $inc: { reads: 1 } });
        }
      }
    } else {
      progress = await ReadingProgress.create({
        user: req.user._id, book: bookId, currentPage, startedAt: new Date()
      });
    }
    
    await progress.save();
    res.json(progress);
  } catch (error) {
    res.status(500).json({ error: 'Error updating progress' });
  }
});

app.get('/api/progress', auth, async (req, res) => {
  try {
    const progress = await ReadingProgress.find({ user: req.user._id })
      .populate('book', 'title author coverIcon pages');
    res.json(progress);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching progress' });
  }
});

// ==================== STATS ====================

app.get('/api/stats', auth, async (req, res) => {
  try {
    const totalBooks = await Book.countDocuments();
    const userBooks = await Book.countDocuments({ createdBy: req.user._id });
    const completedBooks = await ReadingProgress.countDocuments({ user: req.user._id, completed: true });
    const currentlyReading = await ReadingProgress.countDocuments({ user: req.user._id, completed: false });
    
    res.json({
      totalBooks,
      userBooks,
      completedBooks,
      currentlyReading,
      booksRead: req.user.booksRead,
      readingGoal: req.user.readingGoal,
      favorites: req.user.favorites.length
    });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching stats' });
  }
});

// ==================== HTML PAGES ====================

const CSS = `
<style>
  :root {
    --primary: #6C63FF;
    --secondary: #FF6584;
    --accent: #43E97B;
    --dark: #2D3436;
    --light: #F8F9FA;
    --card: #FFFFFF;
    --gradient: linear-gradient(135deg, #6C63FF 0%, #FF6584 100%);
    --shadow: 0 10px 40px rgba(0,0,0,0.1);
    --shadow-hover: 0 20px 60px rgba(0,0,0,0.2);
    --radius: 20px;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    background: #f0f2f5;
    min-height: 100vh;
    color: var(--dark);
  }

  .navbar {
    background: var(--card);
    box-shadow: 0 2px 20px rgba(0,0,0,0.08);
    padding: 15px 0;
    position: sticky;
    top: 0;
    z-index: 1000;
  }

  .nav-container {
    max-width: 1300px;
    margin: 0 auto;
    padding: 0 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
  }

  .nav-brand {
    font-size: 28px;
    font-weight: 800;
    background: var(--gradient);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-decoration: none;
  }

  .nav-links {
    display: flex;
    gap: 15px;
    align-items: center;
    list-style: none;
    flex-wrap: wrap;
  }

  .nav-links a {
    text-decoration: none;
    color: var(--dark);
    font-weight: 500;
    padding: 8px 16px;
    border-radius: 12px;
    transition: all 0.3s;
  }

  .nav-links a:hover, .nav-links a.active {
    background: var(--gradient);
    color: white;
  }

  .btn {
    padding: 10px 24px;
    border: none;
    border-radius: 12px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .btn-primary { background: var(--gradient); color: white; }
  .btn-primary:hover { transform: translateY(-2px); box-shadow: var(--shadow-hover); }
  .btn-outline { background: transparent; border: 2px solid var(--primary); color: var(--primary); }
  .btn-outline:hover { background: var(--primary); color: white; }
  .btn-sm { padding: 6px 14px; font-size: 13px; }
  .btn-danger { background: #ff4757; color: white; }

  .container { max-width: 1300px; margin: 0 auto; padding: 30px 20px; }

  .card {
    background: var(--card);
    border-radius: var(--radius);
    padding: 24px;
    box-shadow: var(--shadow);
    transition: all 0.3s;
    margin-bottom: 20px;
  }

  .card:hover { box-shadow: var(--shadow-hover); }

  .hero {
    background: var(--gradient);
    border-radius: 30px;
    padding: 60px 40px;
    color: white;
    text-align: center;
    margin-bottom: 40px;
  }

  .hero h1 { font-size: 48px; margin-bottom: 16px; }
  .hero p { font-size: 20px; opacity: 0.9; margin-bottom: 30px; }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 24px;
  }

  .book-card {
    background: var(--card);
    border-radius: var(--radius);
    overflow: hidden;
    box-shadow: var(--shadow);
    transition: all 0.3s;
    cursor: pointer;
  }

  .book-card:hover { transform: translateY(-8px); box-shadow: var(--shadow-hover); }

  .book-cover {
    height: 180px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 80px;
  }

  .book-info { padding: 20px; }
  .book-info h3 { font-size: 20px; margin-bottom: 8px; }
  .book-info .author { color: #666; font-size: 14px; margin-bottom: 8px; }

  .book-meta { display: flex; gap: 8px; flex-wrap: wrap; }

  .badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    background: #f0f0f0;
    color: #666;
  }

  .badge-primary { background: #e8e4ff; color: var(--primary); }
  .badge-success { background: #e4ffe8; color: #27ae60; }
  .badge-warning { background: #fff8e4; color: #f39c12; }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 40px;
  }

  .stat-card {
    background: var(--card);
    border-radius: var(--radius);
    padding: 24px;
    text-align: center;
    box-shadow: var(--shadow);
  }

  .stat-card .icon { font-size: 40px; margin-bottom: 10px; }
  .stat-card .number { font-size: 36px; font-weight: 800; color: var(--primary); }
  .stat-card .label { color: #666; font-size: 14px; margin-top: 4px; }

  .form-group { margin-bottom: 20px; }
  .form-group label { display: block; margin-bottom: 8px; font-weight: 600; }

  .form-control {
    width: 100%;
    padding: 12px 16px;
    border: 2px solid #e0e0e0;
    border-radius: 12px;
    font-size: 16px;
    transition: all 0.3s;
    font-family: inherit;
  }

  .form-control:focus { outline: none; border-color: var(--primary); }

  .progress-bar {
    height: 8px;
    background: #e0e0e0;
    border-radius: 10px;
    overflow: hidden;
    margin: 10px 0;
  }

  .progress-fill {
    height: 100%;
    background: var(--gradient);
    border-radius: 10px;
    transition: width 0.5s;
  }

  .alert {
    padding: 14px 20px;
    border-radius: 12px;
    margin-bottom: 20px;
  }

  .alert-error { background: #ffe8e8; color: #c0392b; }
  .alert-success { background: #e8ffe8; color: #27ae60; }

  .hidden { display: none !important; }

  .modal {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.7);
    z-index: 2000;
    align-items: center;
    justify-content: center;
  }

  .modal.active { display: flex; }

  .modal-content {
    background: var(--card);
    border-radius: var(--radius);
    padding: 30px;
    max-width: 600px;
    width: 90%;
    max-height: 80vh;
    overflow-y: auto;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
  }

  .close-btn { background: none; border: none; font-size: 28px; cursor: pointer; }

  .star-rating { display: flex; gap: 4px; cursor: pointer; font-size: 28px; }
  .star-rating span { color: #ddd; transition: color 0.2s; }
  .star-rating span.active { color: #f39c12; }

  .auth-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--gradient);
    padding: 20px;
  }

  .auth-card {
    background: var(--card);
    border-radius: 30px;
    padding: 40px;
    width: 100%;
    max-width: 440px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
  }

  .auth-card h1 { text-align: center; margin-bottom: 30px; font-size: 32px; }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .animate { animation: fadeIn 0.5s ease; }

  @media (max-width: 768px) {
    .hero h1 { font-size: 32px; }
    .hero p { font-size: 16px; }
    .nav-container { flex-direction: column; }
  }
</style>
`;

function getNavbar(user) {
  return `
<div class="navbar">
  <div class="nav-container">
    <a href="/" class="nav-brand">📚 StoryNest</a>
    <div class="nav-links">
      <a href="/">🏠 Home</a>
      <a href="/browse">🔍 Browse</a>
      ${user ? `
        <a href="/dashboard">📊 Dashboard</a>
        <a href="/my-books">📖 My Books</a>
        <a href="/profile">👤 ${user.fullName || user.username}</a>
        <button class="btn btn-sm btn-danger" onclick="logout()">Logout</button>
      ` : `
        <a href="/login"><button class="btn btn-sm btn-outline">Login</button></a>
        <a href="/signup"><button class="btn btn-sm btn-primary">Sign Up</button></a>
      `}
    </div>
  </div>
</div>`;
}

// Helper function to get user from token
async function getUserFromRequest(req) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return null;
    const decoded = jwt.verify(token, JWT_SECRET);
    return await User.findById(decoded.userId);
  } catch(e) {
    return null;
  }
}

// ==================== PAGES ====================

app.get('/', async (req, res) => {
  const user = await getUserFromRequest(req);
  const featuredBooks = await Book.find().sort({ rating: -1 }).limit(6);
  const recentBooks = await Book.find().sort({ createdAt: -1 }).limit(6);

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StoryNest - Discover Your Next Adventure</title>${CSS}</head>
<body>
  ${getNavbar(user)}
  <div class="container">
    <div class="hero animate">
      <h1>📚 Discover Your Next<br>Favorite Book</h1>
      <p>Join thousands of readers exploring amazing stories every day</p>
      ${!user ? '<a href="/signup" class="btn btn-primary" style="font-size:18px; padding:14px 32px;">✨ Start Reading Free</a>' : '<a href="/browse" class="btn btn-primary" style="font-size:18px; padding:14px 32px;">📖 Browse Library</a>'}
    </div>
    <h2 style="margin-bottom:20px;">⭐ Featured Books</h2>
    <div class="grid">${featuredBooks.map(b => `
      <div class="book-card animate" onclick="location.href='/book/${b._id}'">
        <div class="book-cover" style="background:linear-gradient(135deg,#667eea22,#764ba244);">${b.coverIcon}</div>
        <div class="book-info"><h3>${b.title}</h3><p class="author">by ${b.author}</p>
          <div class="book-meta"><span class="badge badge-primary">${b.genre}</span><span class="badge badge-warning">⭐ ${b.rating.toFixed(1)}</span><span class="badge">${b.age}</span></div>
        </div>
      </div>`).join('')}</div>
    <h2 style="margin:40px 0 20px;">🆕 Recently Added</h2>
    <div class="grid">${recentBooks.map(b => `
      <div class="book-card animate" onclick="location.href='/book/${b._id}'">
        <div class="book-cover" style="background:linear-gradient(135deg,#a18cd133,#fbc2eb55);">${b.coverIcon}</div>
        <div class="book-info"><h3>${b.title}</h3><p class="author">by ${b.author}</p>
          <div class="book-meta"><span class="badge badge-primary">${b.genre}</span><span class="badge">${b.pages} pages</span></div>
        </div>
      </div>`).join('')}</div>
  </div>
  <script>
    function getToken() { return localStorage.getItem('token'); }
    async function logout() { localStorage.removeItem('token'); localStorage.removeItem('user'); window.location.href = '/'; }
  </script>
</body></html>`);
});

app.get('/login', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - StoryNest</title>${CSS}</head>
<body>
<div class="auth-container">
  <div class="auth-card animate">
    <div style="text-align:center;font-size:60px;">📚</div>
    <h1>Welcome Back</h1>
    <div id="error" class="alert alert-error hidden"></div>
    <form id="loginForm">
      <div class="form-group"><label>Email</label><input type="email" id="email" class="form-control" required></div>
      <div class="form-group"><label>Password</label><input type="password" id="password" class="form-control" required></div>
      <button type="submit" class="btn btn-primary" style="width:100%;">Login</button>
    </form>
    <p style="text-align:center;margin-top:20px;">Don't have an account? <a href="/signup">Sign Up</a></p>
    <p style="text-align:center;"><a href="/">← Home</a></p>
  </div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const errorDiv = document.getElementById('error');
  errorDiv.classList.add('hidden');
  
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, password})
    });
    const data = await res.json();
    
    if (res.ok) {
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      window.location.href = '/';
    } else {
      errorDiv.textContent = data.error || 'Login failed';
      errorDiv.classList.remove('hidden');
    }
  } catch(err) {
    errorDiv.textContent = 'Network error. Please try again.';
    errorDiv.classList.remove('hidden');
  }
});
</script>
</body></html>`);
});

app.get('/signup', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign Up - StoryNest</title>${CSS}</head>
<body>
<div class="auth-container">
  <div class="auth-card animate">
    <div style="text-align:center;font-size:60px;">✨</div>
    <h1>Join StoryNest</h1>
    <div id="error" class="alert alert-error hidden"></div>
    <div id="success" class="alert alert-success hidden"></div>
    <form id="signupForm">
      <div class="form-group"><label>Full Name</label><input type="text" id="fullName" class="form-control"></div>
      <div class="form-group"><label>Username *</label><input type="text" id="username" class="form-control" required></div>
      <div class="form-group"><label>Email *</label><input type="email" id="email" class="form-control" required></div>
      <div class="form-group"><label>Password * (min 6 chars)</label><input type="password" id="password" class="form-control" required minlength="6"></div>
      <div class="form-group"><label>Confirm Password *</label><input type="password" id="confirmPassword" class="form-control" required></div>
      <button type="submit" class="btn btn-primary" style="width:100%;">Create Account</button>
    </form>
    <p style="text-align:center;margin-top:20px;">Already have an account? <a href="/login">Login</a></p>
    <p style="text-align:center;"><a href="/">← Home</a></p>
  </div>
</div>
<script>
document.getElementById('signupForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const fullName = document.getElementById('fullName').value;
  const username = document.getElementById('username').value;
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;
  const errorDiv = document.getElementById('error');
  const successDiv = document.getElementById('success');
  
  errorDiv.classList.add('hidden');
  successDiv.classList.add('hidden');
  
  if (password !== confirmPassword) {
    errorDiv.textContent = 'Passwords do not match';
    errorDiv.classList.remove('hidden');
    return;
  }
  
  if (password.length < 6) {
    errorDiv.textContent = 'Password must be at least 6 characters';
    errorDiv.classList.remove('hidden');
    return;
  }
  
  try {
    const res = await fetch('/api/auth/signup', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({fullName, username, email, password})
    });
    const data = await res.json();
    
    if (res.ok) {
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      successDiv.textContent = 'Account created! Redirecting...';
      successDiv.classList.remove('hidden');
      setTimeout(() => { window.location.href = '/'; }, 1500);
    } else {
      errorDiv.textContent = data.error || 'Signup failed';
      errorDiv.classList.remove('hidden');
    }
  } catch(err) {
    errorDiv.textContent = 'Network error. Please try again.';
    errorDiv.classList.remove('hidden');
  }
});
</script>
</body></html>`);
});

// Browse page
app.get('/browse', async (req, res) => {
  const user = await getUserFromRequest(req);
  const genres = ['All', 'Fiction', 'Non-Fiction', 'Mystery', 'Fantasy', 'Science Fiction', 'Romance', 'Horror', 'Adventure', 'Biography', 'History', 'Science'];

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Browse Books - StoryNest</title>${CSS}</head>
<body>
${getNavbar(user)}
<div class="container">
  <h1 style="margin-bottom:30px;">🔍 Browse Library</h1>
  <div style="display:flex;gap:15px;flex-wrap:wrap;margin-bottom:30px;align-items:center;">
    <input type="text" id="searchInput" class="form-control" placeholder="Search books..." style="flex:1;min-width:200px;">
    <select id="genreFilter" class="form-control" style="max-width:200px;">${genres.map(g => `<option value="${g}">${g}</option>`).join('')}</select>
    <select id="sortBy" class="form-control" style="max-width:200px;">
      <option value="newest">Newest</option><option value="rating">Highest Rated</option><option value="popular">Most Read</option><option value="title">Title A-Z</option>
    </select>
    ${user ? '<button class="btn btn-primary" onclick="showAddModal()">+ Add Book</button>' : ''}
  </div>
  <div class="grid" id="booksGrid"></div>
</div>
${user ? `
<div class="modal" id="addModal">
  <div class="modal-content">
    <div class="modal-header"><h2>Add New Book</h2><button class="close-btn" onclick="closeModal()">&times;</button></div>
    <div class="form-group"><label>Title *</label><input type="text" id="addTitle" class="form-control"></div>
    <div class="form-group"><label>Author *</label><input type="text" id="addAuthor" class="form-control"></div>
    <div class="form-group"><label>Description</label><textarea id="addDesc" class="form-control"></textarea></div>
    <div class="form-group"><label>Genre</label><select id="addGenre" class="form-control">${genres.slice(1).map(g => `<option>${g}</option>`).join('')}</select></div>
    <div class="form-group"><label>Age Range</label><input type="text" id="addAge" class="form-control" value="All ages"></div>
    <div class="form-group"><label>Pages</label><input type="number" id="addPages" class="form-control" value="100"></div>
    <button class="btn btn-primary" onclick="addBook()" style="width:100%;">Add Book</button>
  </div>
</div>` : ''}
<script>
const token = localStorage.getItem('token');
async function fetchBooks() {
  const search = document.getElementById('searchInput').value;
  const genre = document.getElementById('genreFilter').value;
  const sort = document.getElementById('sortBy').value;
  const sortMap = {newest:'',rating:'rating',popular:'popular',title:'title'};
  const res = await fetch('/api/books?search='+search+'&genre='+genre+'&sort='+sortMap[sort]);
  const books = await res.json();
  document.getElementById('booksGrid').innerHTML = books.map(b => 
    '<div class="book-card animate" onclick="location.href=\\'/book/'+b._id+'\\'"><div class="book-cover" style="background:linear-gradient(135deg,#667eea22,#764ba244);">'+b.coverIcon+'</div><div class="book-info"><h3>'+b.title+'</h3><p class="author">by '+b.author+'</p><div class="book-meta"><span class="badge badge-primary">'+b.genre+'</span><span class="badge badge-warning">⭐ '+b.rating.toFixed(1)+'</span><span class="badge">'+b.pages+'p</span></div></div></div>'
  ).join('');
}
function showAddModal() { document.getElementById('addModal').classList.add('active'); }
function closeModal() { document.getElementById('addModal').classList.remove('active'); }
async function addBook() {
  const res = await fetch('/api/books', {
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body:JSON.stringify({
      title:document.getElementById('addTitle').value,
      author:document.getElementById('addAuthor').value,
      description:document.getElementById('addDesc').value,
      genre:document.getElementById('addGenre').value,
      age:document.getElementById('addAge').value,
      pages:parseInt(document.getElementById('addPages').value)
    })
  });
  if(res.ok) { closeModal(); fetchBooks(); }
  else alert('Error adding book');
}
document.getElementById('searchInput').addEventListener('input', fetchBooks);
document.getElementById('genreFilter').addEventListener('change', fetchBooks);
document.getElementById('sortBy').addEventListener('change', fetchBooks);
fetchBooks();
function getToken() { return localStorage.getItem('token'); }
async function logout() { localStorage.removeItem('token'); localStorage.removeItem('user'); window.location.href = '/'; }
</script>
</body></html>`);
});

// Book detail page
app.get('/book/:id', async (req, res) => {
  const user = await getUserFromRequest(req);
  const book = await Book.findById(req.params.id)
    .populate('createdBy', 'username avatar')
    .populate('reviews.user', 'username avatar');
  
  if (!book) return res.status(404).send('Book not found');

  let isFavorited = false;
  if (user) {
    isFavorited = user.favorites.includes(book._id);
  }

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${book.title} - StoryNest</title>${CSS}</head>
<body>
${getNavbar(user)}
<div class="container">
  <div class="card animate" style="display:flex;gap:30px;flex-wrap:wrap;">
    <div style="font-size:120px;text-align:center;min-width:200px;background:linear-gradient(135deg,#667eea22,#764ba244);border-radius:20px;padding:40px;">${book.coverIcon}</div>
    <div style="flex:1;min-width:280px;">
      <h1 style="font-size:36px;margin-bottom:8px;">${book.title}</h1>
      <p style="font-size:20px;color:#666;margin-bottom:16px;">by ${book.author}</p>
      <div class="book-meta" style="margin-bottom:20px;">
        <span class="badge badge-primary">${book.genre}</span>
        <span class="badge badge-warning">⭐ ${book.rating.toFixed(1)} (${book.totalRatings} reviews)</span>
        <span class="badge">${book.age}</span>
        <span class="badge">${book.pages} pages</span>
        <span class="badge badge-success">${book.reads} reads</span>
      </div>
      <p style="font-size:16px;line-height:1.6;color:#555;margin-bottom:20px;">${book.description}</p>
      ${user ? `
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn ${isFavorited ? 'btn-primary' : 'btn-outline'}" onclick="toggleFavorite('${book._id}')">${isFavorited ? '❤️ Favorited' : '🤍 Add to Favorites'}</button>
          <button class="btn btn-outline" onclick="startReading('${book._id}')">📖 Start Reading</button>
        </div>` : '<p><a href="/login">Login</a> to save favorites and track reading.</p>'}
    </div>
  </div>
  ${user ? `
  <div class="card animate" style="margin-top:30px;">
    <h2>📝 Add Review</h2>
    <div class="star-rating" id="starRating">${[1,2,3,4,5].map(i => '<span onclick="setRating('+i+')" id="star'+i+'">★</span>').join('')}</div>
    <textarea id="reviewText" class="form-control" placeholder="Write your review..." style="margin:15px 0;"></textarea>
    <button class="btn btn-primary" onclick="submitReview('${book._id}')">Submit Review</button>
  </div>` : ''}
  <div class="card animate" style="margin-top:30px;">
    <h2>💬 Reviews (${book.reviews.length})</h2>
    ${book.reviews.length === 0 ? '<p style="color:#999;margin-top:15px;">No reviews yet.</p>' : 
      book.reviews.map(r => `
        <div style="border-bottom:1px solid #eee;padding:20px 0;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <strong>${r.user.avatar||'👤'} ${r.user.username}</strong>
            <span style="color:#f39c12;">${'★'.repeat(r.rating)}${'☆'.repeat(5-r.rating)}</span>
          </div>
          <p style="margin-top:8px;color:#555;">${r.text}</p>
          <small style="color:#999;">${new Date(r.date).toLocaleDateString()}</small>
        </div>`).join('')
    }
  </div>
</div>
<script>
let rating = 0;
const token = localStorage.getItem('token');
function setRating(r) { rating = r; for(let i=1;i<=5;i++) document.getElementById('star'+i).classList.toggle('active',i<=r); }
async function submitReview(bookId) {
  const text = document.getElementById('reviewText').value;
  if(!rating) return alert('Select a rating');
  if(!text) return alert('Write a review');
  await fetch('/api/books/'+bookId+'/review', {
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body:JSON.stringify({text,rating})
  });
  location.reload();
}
async function toggleFavorite(bookId) {
  await fetch('/api/books/'+bookId+'/favorite', {method:'POST',headers:{'Authorization':'Bearer '+token}});
  location.reload();
}
async function startReading(bookId) {
  await fetch('/api/progress', {
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body:JSON.stringify({bookId,currentPage:0})
  });
  location.reload();
}
function getToken() { return localStorage.getItem('token'); }
async function logout() { localStorage.removeItem('token'); localStorage.removeItem('user'); window.location.href = '/'; }
</script>
</body></html>`);
});

// Dashboard
app.get('/dashboard', async (req, res) => {
  const user = await getUserFromRequest(req);
  if (!user) return res.redirect('/login');

  const stats = {
    totalBooks: await Book.countDocuments(),
    userBooks: await Book.countDocuments({ createdBy: user._id }),
    completedBooks: await ReadingProgress.countDocuments({ user: user._id, completed: true }),
    currentlyReading: await ReadingProgress.countDocuments({ user: user._id, completed: false }),
  };

  const recentProgress = await ReadingProgress.find({ user: user._id })
    .populate('book', 'title coverIcon pages')
    .sort({ lastRead: -1 }).limit(5);

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard - StoryNest</title>${CSS}</head>
<body>
${getNavbar(user)}
<div class="container">
  <h1 style="margin-bottom:30px;">📊 Your Dashboard</h1>
  <div class="stats-grid animate">
    <div class="stat-card"><div class="icon">📚</div><div class="number">${stats.totalBooks}</div><div class="label">Total Books</div></div>
    <div class="stat-card"><div class="icon">✍️</div><div class="number">${stats.userBooks}</div><div class="label">Books You Added</div></div>
    <div class="stat-card"><div class="icon">✅</div><div class="number">${stats.completedBooks}</div><div class="label">Completed</div></div>
    <div class="stat-card"><div class="icon">📖</div><div class="number">${stats.currentlyReading}</div><div class="label">Reading Now</div></div>
  </div>
  <div class="card animate" style="margin-bottom:30px;">
    <h2>🎯 Reading Goal</h2>
    <p style="font-size:18px;margin:10px 0;">${user.booksRead} / ${user.readingGoal} books read</p>
    <div class="progress-bar"><div class="progress-fill" style="width:${Math.min((user.booksRead/user.readingGoal)*100,100)}%"></div></div>
  </div>
  <div class="card animate">
    <h2>📖 Continue Reading</h2>
    ${recentProgress.length === 0 ? '<p style="color:#999;">Start reading some books!</p>' : 
      recentProgress.map(p => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:15px 0;border-bottom:1px solid #eee;cursor:pointer;" onclick="location.href='/book/${p.book._id}'">
          <div style="display:flex;align-items:center;gap:15px;">
            <span style="font-size:40px;">${p.book.coverIcon}</span>
            <div>
              <strong>${p.book.title}</strong>
              <p style="color:#666;font-size:14px;">Page ${p.currentPage} of ${p.book.pages}</p>
              <div class="progress-bar" style="width:200px;"><div class="progress-fill" style="width:${(p.currentPage/p.book.pages)*100}%"></div></div>
            </div>
          </div>
          ${p.completed ? '<span class="badge badge-success">Completed ✅</span>' : '<span class="badge badge-warning">Reading...</span>'}
        </div>`).join('')}
  </div>
</div>
<script>function getToken(){return localStorage.getItem('token')}async function logout(){localStorage.removeItem('token');localStorage.removeItem('user');window.location.href='/'}</script>
</body></html>`);
});

// Profile page
app.get('/profile', async (req, res) => {
  const user = await getUserFromRequest(req);
  if (!user) return res.redirect('/login');

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Profile - StoryNest</title>${CSS}</head>
<body>
${getNavbar(user)}
<div class="container">
  <div class="card animate" style="max-width:600px;margin:0 auto;">
    <div style="text-align:center;font-size:80px;margin-bottom:20px;">${user.avatar}</div>
    <h1 style="text-align:center;">${user.fullName || user.username}</h1>
    <p style="text-align:center;color:#666;">@${user.username}</p>
    <p style="text-align:center;margin:10px 0;">${user.bio}</p>
    <p style="text-align:center;color:#999;">Joined ${new Date(user.joinedDate).toLocaleDateString()}</p>
    <div style="margin-top:30px;">
      <div class="form-group"><label>Full Name</label><input type="text" id="editName" class="form-control" value="${user.fullName||''}"></div>
      <div class="form-group"><label>Bio</label><textarea id="editBio" class="form-control">${user.bio||''}</textarea></div>
      <div class="form-group"><label>Reading Goal (books/year)</label><input type="number" id="editGoal" class="form-control" value="${user.readingGoal}"></div>
      <button class="btn btn-primary" onclick="updateProfile()" style="width:100%;">Save Changes</button>
    </div>
  </div>
</div>
<script>
const token = localStorage.getItem('token');
async function updateProfile() {
  const res = await fetch('/api/auth/profile', {
    method:'PUT',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body:JSON.stringify({
      fullName:document.getElementById('editName').value,
      bio:document.getElementById('editBio').value,
      readingGoal:parseInt(document.getElementById('editGoal').value)
    })
  });
  if(res.ok){alert('Profile updated!');location.reload();}
  else alert('Error updating profile');
}
function getToken(){return localStorage.getItem('token')}
async function logout(){localStorage.removeItem('token');localStorage.removeItem('user');window.location.href='/'}
</script>
</body></html>`);
});

// My Books page
app.get('/my-books', async (req, res) => {
  const user = await getUserFromRequest(req);
  if (!user) return res.redirect('/login');

  const myBooks = await Book.find({ createdBy: user._id }).sort({ createdAt: -1 });

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>My Books - StoryNest</title>${CSS}</head>
<body>
${getNavbar(user)}
<div class="container">
  <h1 style="margin-bottom:30px;">📚 My Books</h1>
  ${myBooks.length === 0 ? '<p style="color:#999;">You haven\'t added any books yet. <a href="/browse">Browse the library</a>!</p>' : ''}
  <div class="grid">
    ${myBooks.map(b => `
      <div class="book-card animate" onclick="location.href='/book/${b._id}'">
        <div class="book-cover" style="background:linear-gradient(135deg,#a18cd122,#fbc2eb44);">${b.coverIcon}</div>
        <div class="book-info"><h3>${b.title}</h3><p class="author">by ${b.author}</p>
          <div class="book-meta"><span class="badge badge-primary">${b.genre}</span><span class="badge">${b.reads} reads</span><span class="badge badge-warning">⭐ ${b.rating.toFixed(1)}</span></div>
        </div>
      </div>`).join('')}
  </div>
</div>
<script>function getToken(){return localStorage.getItem('token')}async function logout(){localStorage.removeItem('token');localStorage.removeItem('user');window.location.href='/'}</script>
</body></html>`);
});

module.exports = app;
