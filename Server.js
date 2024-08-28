const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const port = 5000;

app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'my_database'
});

db.connect(err => {
    if (err) throw err;
    console.log('Database connected !');
});

app.post('/register/customer', (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).send('Server error.');
        }

        if (checkResults.length > 0) {
            return res.status(400).send('Email already exists.');
        }

        const verificationToken = jwt.sign({ email }, 'secret', { expiresIn: '1h' });

        db.query('INSERT INTO users SET ?', {
            first_name: firstName,
            last_name: lastName,
            email,
            password,
            role: 'customer',
            is_verified: true,
            verification_token: verificationToken
        },
            (insertErr, insertResults) => {
                if (insertErr) {
                    return res.status(500).send('Server error.');
                }
                res.status(201).send('Registration successful! Please verify your email.');
            });
    });
});

app.post('/register/admin', (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).send('Server error.');
        }

        if (checkResults.length > 0) {
            return res.status(400).send('Email already exists.');
        }

        const verificationToken = jwt.sign({ email }, 'secret', { expiresIn: '1h' });

        db.query('INSERT INTO users SET ?', {
            first_name: firstName,
            last_name: lastName,
            email,
            password,
            role: 'admin',
            is_verified: true,
            verification_token: verificationToken
        },
            (insertErr, insertResults) => {
                if (insertErr) {
                    return res.status(500).send('Server error.');
                }
                res.status(201).send('Registration successful! Please verify your email.');
            });
    });
});


app.get('/verify/:token', (req, res) => {
    const { token } = req.params;
    jwt.verify(token, 'secret', (err, decoded) => {
        if (err) return res.status(400).send('Invalid or expired token');

        db.query('UPDATE users SET is_verified = 1 WHERE email = ?', [decoded.email], (error, results) => {
            if (error) throw error;
            res.send('Email verified successfully!');
        });
    });
});

app.post('/login/admin', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email and password are required');
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
        if (error) return res.status(500).send('Database error');

        const user = results[0];

        if (!user) {
            return res.status(404).send('User does not exist');
        }

        if (user.role !== 'admin') {
            if (user.role === 'customer') {
                return res.status(403).send('You are not allowed to login from here');
            } else {
                return res.status(403).send('Access denied');
            }
        }

        if (user.password !== password) {
            return res.status(401).send('Incorrect password');
        }

        const token = jwt.sign({ id: user.id, role: user.role }, 'secret', { expiresIn: '1h' });
        res.json({ token });

    });
});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
