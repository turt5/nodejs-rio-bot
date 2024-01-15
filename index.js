const express = require('express');
const multer = require('multer');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
require('dotenv').config();

const app = express();
const port = process.env.PORT;

const connection = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage: storage });

app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

app.use('/uploads', express.static('uploads'));

app.post('/users', upload.single('profilePicture'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO Users (name, email, password, profilePicture) VALUES (?, ?, ?, ?)';
    const values = [name, email, hashedPassword, req.file ? req.file.filename : null];

    connection.query(sql, values, (err, result) => {
      if (err) {
        console.error('Error creating user:', err);
        res.status(500).send('Internal Server Error');
        return;
      }

      const newUser = {
        id: result.insertId,
        name,
        email,
        profilePicture: req.file ? req.file.filename : null,
      };

      res.status(201).json(newUser);
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM Users WHERE email = ?';
    const values = [email];

    connection.query(sql, values, async (err, results) => {
      if (err) {
        console.error('Error during login:', err);
        res.status(500).send('Internal Server Error');
        return;
      }

      const user = results[0];

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        return res.status(200).json({ userId: user.id, status: 'true' });
      } else {
        return res.status(401).json({ status: 'false' });
      }
    });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/users/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const sql = 'SELECT id, name, email, profilePicture FROM Users WHERE id = ?';
    const values = [userId];

    connection.query(sql, values, (err, results) => {
      if (err) {
        console.error('Error fetching user data:', err);
        res.status(500).send('Internal Server Error');
        return;
      }

      const user = results[0];

      if (user) {
        res.status(200).json(user);
      } else {
        res.status(404).json({ message: 'User not found' });
      }
    });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
