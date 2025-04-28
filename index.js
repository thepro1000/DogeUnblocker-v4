import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import session from 'express-session';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

// Failed login attempt tracking
const failedAttempts = {}; // { [ip]: { count, blockUntil } }

const MAX_ATTEMPTS = 5;
const BLOCK_TIME = 24 * 60 * 60 * 1000; // 24 hours

// Setup session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Parse form data
app.use(express.urlencoded({ extended: true }));

// Middleware to protect static content
app.use('/static', (req, res, next) => {
    if (!req.session.username) {
        return res.redirect('/login');
    }
    next();
});

// Serve static files (like /static/index.html)
app.use('/static', express.static(path.join(__dirname, 'static')));

// GET /login — Show login form
app.get('/login', (req, res) => {
    res.send(`
        <html>
            <head><title>Login</title></head>
            <body>
                <h1>Login</h1>
                <form method="POST" action="/login">
                    <input type="text" name="username" placeholder="Username" required />
                    <input type="password" name="password" placeholder="Password" required />
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
    `);
});

// POST /login — Handle login logic
app.post('/login', (req, res) => {
    const ip = req.ip;
    const { username, password } = req.body;

    if (!failedAttempts[ip]) {
        failedAttempts[ip] = { count: 0, blockUntil: 0 };
    }

    const client = failedAttempts[ip];

    // Block check
    if (client.count >= MAX_ATTEMPTS && Date.now() < client.blockUntil) {
        return res.redirect('/blocked');
    }

    const users = JSON.parse(process.env.USERS || '{}');

    if (users[username] && users[username] === password) {
        // Success
        req.session.username = username;
        client.count = 0; // Reset failed attempts
        return res.send(`
            <html>
                <head><title>Login Success</title></head>
                <body>
                    <script>
                        alert("Success! Redirecting...");
                        window.location.href = "/static/index.html";
                    </script>
                </body>
            </html>
        `);
    } else {
        // Failed login
        client.count++;

        if (client.count >= MAX_ATTEMPTS) {
            client.blockUntil = Date.now() + BLOCK_TIME;
            return res.redirect('/blocked');
        }

        return res.send(`
            <html>
                <head><title>Login Failed</title></head>
                <body>
                    <script>
                        alert("Nope! Try again!");
                        window.location.href = "/login";
                    </script>
                </body>
            </html>
        `);
    }
});

// GET /blocked — Too many failed attempts
app.get('/blocked', (req, res) => {
    res.send(`
        <html>
            <head><title>Blocked</title></head>
            <body>
                <script>
                    alert("You are blocked for 24 hours due to too many failed login attempts.");
                    setTimeout(() => {
                        window.location.href = "https://www.google.com";
                    }, 3000);
                </script>
            </body>
        </html>
    `);
});

// GET /logout — Clears session
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Optional: redirect root / to login or index if already logged in
app.get('/', (req, res) => {
    if (req.session.username) {
        return res.redirect('/static/index.html');
    }
    res.redirect('/login');
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
