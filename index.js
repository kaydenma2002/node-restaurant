const express = require("express");
const app = express();
const port = 3000;
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');

const generateAccessToken = require("./generateAccessToken");
const util = require("util"); // To use promisify

const db = mysql.createPool({
  connectionLimit: 100,
  host: "127.0.0.1",
  user: "root",
  password: "password",

  database: "restaurant",
  port: "3306"
});

const connectionQuery = util.promisify(db.query).bind(db); // Promisify the query function

app.use(express.json());

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const sqlSearch = "SELECT * FROM users WHERE email = ?";
    const searchResults = await connectionQuery(sqlSearch, [email]);

    if (searchResults.length === 0) {
      return res.sendStatus(404);
    }
    
    const hashedPassword = searchResults[0].password.replace('$2a$','$2y$');
    
    if (await bcrypt.compare(password, hashedPassword)) {
      
      const token = generateAccessToken({ user: email });   
      
      res.json({ accessToken: token });
    } else {
      
      res.status(401).send("Password incorrect");
    }
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});
app.get('/api/validate-token', (req, res) => {
  const token = req.query.token;
  
  if (!token) {
    return res.status(400).json({ error: 'Token not provided' });
  }

  jwt.verify(token, 'access-token', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    res.json({ valid: true });
  });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

