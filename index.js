const express = require("express");
const app = express();
const port = 3001;
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const generateAccessToken = require("./generateAccessToken");
const util = require("util"); // To use promisify

const db = mysql.createPool({
  connectionLimit: 100,
  host: "127.0.0.1",
  user: "root",
  password: "password",

  database: "restaurant",
  port: "3306",
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
    const user = searchResults[0];
    const hashedPassword = searchResults[0].password.replace("$2a$", "$2y$");
    if (bcrypt.compare(password, hashedPassword)) {
      const token = generateAccessToken({ user: user });
      res.json({ user: user,token: token });
    } else {
      res.status(401).send("Password incorrect");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});
app.get("/api/validate-token", (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(400).json({ error: "Token not provided" });
  }

  jwt.verify(token, "token", (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid token" });
    }
    
    if (decoded.user.user_type === "0" || decoded.user.user_type === "1") {
      console.log(decoded.user.user_type)
      res.json({ valid: true, userType: decoded.user.user_type });
      
    } else {
      res.status(401).json({ error: "Invalid user type" });
    }
  });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
