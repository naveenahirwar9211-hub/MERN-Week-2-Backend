const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json()); // JSON डेटा को प्रोसेस करने के लिए

// 1. MongoDB Database Connection
// नोट: असली प्रोजेक्ट में इसे .env फाइल में रखते हैं
const MONGO_URI = 'mongodb+srv://testuser:testpass@cluster0.mongodb.net/notesdb?retryWrites=true&w=majority';
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully'))
  .catch(err => console.log('DB Connection Error:', err));

// 2. Database Models (Schemas)
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

const NoteSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true }
});
const Note = mongoose.model('Note', NoteSchema);

// 3. JWT Authentication Middleware (राउटर को सिक्योर करने के लिए)
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access Denied. No token provided.' });

    try {
        const verified = jwt.verify(token.replace('Bearer ', ''), 'MySuperSecretKey123');
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid Token' });
    }
};

// ==========================================
// User Authentication API (Task 2)
// ==========================================

// Register Route (पासवर्ड एन्क्रिप्शन के साथ)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Password Hashing using bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (err) {
        res.status(500).json({ error: 'Registration failed or email already exists.' });
    }
});

// Login Route (JWT जेनेरेट करने के लिए)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'User not found' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

        // Generate JWT Token
        const token = jwt.sign({ userId: user._id }, 'MySuperSecretKey123', { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// ==========================================
// Notes CRUD API / To-Do API (Task 1 & Mini Project)
// ==========================================

// Create a Note (सिर्फ लॉगिन यूज़र के लिए)
app.post('/api/notes', authenticateToken, async (req, res) => {
    try {
        const newNote = new Note({
            userId: req.user.userId,
            title: req.body.title,
            content: req.body.content
        });
        const savedNote = await newNote.save();
        res.status(201).json(savedNote);
    } catch (err) {
        res.status(500).json({ error: 'Failed to create note' });
    }
});

// Read all Notes of the logged-in user
app.get('/api/notes', authenticateToken, async (req, res) => {
    try {
        const notes = await Note.find({ userId: req.user.userId });
        res.json(notes);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch notes' });
    }
});

// Update a Note
app.put('/api/notes/:id', authenticateToken, async (req, res) => {
    try {
        const updatedNote = await Note.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.userId },
            { title: req.body.title, content: req.body.content },
            { new: true }
        );
        if (!updatedNote) return res.status(404).json({ error: 'Note not found' });
        res.json({ message: 'Note updated successfully', updatedNote });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update note' });
    }
});

// Delete a Note
app.delete('/api/notes/:id', authenticateToken, async (req, res) => {
    try {
        const deletedNote = await Note.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
        if (!deletedNote) return res.status(404).json({ error: 'Note not found' });
        res.json({ message: 'Note deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete note' });
    }
});

// Server Listen
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
