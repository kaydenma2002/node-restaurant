const express = require("express");
const cors = require("cors");  // Import the cors package
const app = express();
const port = 3000;
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Pusher = require('pusher');
const generateAccessToken = require("./generateAccessToken");
const util = require("util"); // To use promisify
const https = require("https"); // Import the https module
const fs = require("fs"); 
const bodyParser= require('body-parser');


const db = mysql.createPool({
  connectionLimit: 100,
  host: "127.0.0.1",
  user: "root",
  password: "password",

  database: "restaurant",
  port: "3306",
});
const sslOptions = {
  key: fs.readFileSync("./domain.pem"),
  cert: fs.readFileSync("./certificate.pem"),
};
const allowedOrigins = ["https://localhost:5173","https://localhost:5174","https://localhost:3001","https://127.0.0.1:3001"];
const corsOptions = {
  origin: allowedOrigins,  // Specify the allowed origin
  methods: "POST",            // Specify allowed HTTP methods
  optionsSuccessStatus: 200      // Specify the success status for preflight requests
};

const connectionQuery = util.promisify(db.query).bind(db); // Promisify the query function
app.use(cors(corsOptions));
app.use(express.urlencoded());
app.use(bodyParser.json());
app.use(express.json());

const pusher = new Pusher({
  appId: '1557217',
  key: '68572aaa73079990a7d7',
  secret: '013e1f32ddf8a02a3118',
  cluster: 'mt1',
  useTLS: true,
})
app.post('/send-message', (req, res) => {

  pusher.trigger(`private-super-admin-owner-chat.${req.body.super_admin_id}.${req.body.owner_id}`, 'SuperAdminOwnerChat', {
    "message": req.body.message,
    "super_admin_id": req.body.super_admin_id,
    "owner_id":req.body.owner_id,
    "type":req.body.type
});

  res.sendStatus(200);
});
app.post('/auth', (req, res) => {
  const socketId = req.body.socket_id;
  const channelName = req.body.channel_name;

  // You can implement your own authentication logic here
  // For example, check if the user is authorized to subscribe to this private channel
  // Generate a presence channel user info or return an empty object if unauthorized

  const authData = pusher.authenticate(socketId, channelName, {
    user_id: req.body.user_id, // Replace with the user's unique identifier
    // Additional user data if needed
  });

  res.send(authData);
});
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const sqlSearch = "SELECT * FROM users WHERE email = ?";
    const searchResults = await connectionQuery(sqlSearch, [email]);

    if (searchResults.length === 0) {
      return res.sendStatus(404);
    }
    const user = searchResults[0];
    const hashedPassword = (searchResults[0].password).replace("$2y$", "$2a$");
    
    
    if (await bcrypt.compare(password, hashedPassword)) {
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
app.post("/api/validate-token", (req, res) => {
  
  const token = req.body.token;
  
  if (!token) {
    return res.status(400).json({ error: "Token not provided" });
  }

  jwt.verify(token, "token", (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid token" });
    }
    
    if (decoded.user.user_type === "0" || decoded.user.user_type === "1") {
      console.log(decoded.user.user_type)
      res.json({ valid: true, userType: decoded.user.user_type,user: decoded.user });

    } else {
      res.status(401).json({ error: "Invalid user type" });
    }
  });
});
const server = https.createServer(sslOptions, app);

server.listen(443, () => {
  console.log(`Example app listening on port ${port}`);
});






