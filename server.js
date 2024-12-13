
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');


const app = express();
app.use(bodyParser.json());


mongoose.connect('mongodb://localhost:27017/blog', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});


const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);


const blogSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    comments: [{ content: String, commenter: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } }],
});
const Blog = mongoose.model('Blog', blogSchema);

const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(403).send('Access denied');

    jwt.verify(token, 'secretKey', (err, user) => {
        if (err) return res.status(403).send('Access denied');
        req.user = user;
        next();
    });
};


app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
        username,
        password: hashedPassword
    });

    try {
        await newUser.save();
        res.status(201).send('User registered');
    } catch (error) {
        res.status(400).send(error);
    }
});


app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) return res.status(404).send('User not found');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid credentials');

    const token = jwt.sign({ id: user._id, username: user.username }, 'secretKey', { expiresIn: '1h' });
    res.json({ token });
});


app.post('/api/blog', authenticateJWT, async (req, res) => {
    const { title, content } = req.body;
    const blog = new Blog({
        title,
        content,
        author: req.user.id,
    });

    try {
        await blog.save();
        res.status(201).send('Blog post created');
    } catch (error) {
        res.status(400).send(error);
    }
});


app.get('/api/blog', async (req, res) => {
    const blogs = await Blog.find().populate('author', 'username').populate('comments.commenter', 'username');
    res.json(blogs);
});


app.post('/api/blog/:id/comment', authenticateJWT, async (req, res) => {
    const { content } = req.body;
    const blog = await Blog.findById(req.params.id);

    if (!blog) return res.status(404).send('Blog post not found');

    blog.comments.push({ content, commenter: req.user.id });
    await blog.save();
    res.status(201).send('Comment added');
});


const PORT = process.env.PORT || 2002;
app.listen(PORT, () => {
    console.log(`Server running on port no: ${PORT}`);
});
