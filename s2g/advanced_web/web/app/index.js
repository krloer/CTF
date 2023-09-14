const express = require("express");
const jwt = require("jsonwebtoken");
const mariadb = require("mariadb");
const crypto = require("crypto");
var cookies = require("cookie-parser");
const bodyParser = require("body-parser");

const app = express();
const port = 1337;

app.set("view engine", "ejs");
app.use(cookies());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const pool = mariadb.createPool({
  host: "db",
  user: "root",
  password: "a00e2a2b98c6c8b6ef741aeb0715d2b4",
  database: "nonsense",
  connectionLimit: 100,
});

const key = crypto.randomBytes(32).toString("hex");

app.get("/", async (req, res) => {
  const cookie = req.cookies.jwt;
  if (!cookie) {
    res.redirect("/register");
    return;
  }
  token = jwt.verify(cookie, key, async (err, token) => {
    if (err) {
      res.redirect("/register");
      return;
    }
    if (!token.username) {
      res.redirect("/register");
      return;
    }
    const connection = await pool.getConnection();
    const userIds = await connection.query(
      "SELECT id FROM users WHERE username = ?",
      [token.username]
    );
    if (userIds.length === 0) {
      res.redirect("/register");
      return;
    }
    const userId = userIds[0].id;
    const notes = await connection.query(
      "SELECT * FROM notes WHERE user_id = ?",
      [userId]
    );
    res.render("index", { notes });
  });
});

app.post("/new", async (req, res) => {
  const cookie = req.cookies.jwt;
  if (!cookie) {
    res.redirect("/register");
    return;
  }
  jwt.verify(cookie, key, async (err, token) => {
    if (err) {
      res.redirect("/register");
      return;
    }
    if (!token.username) {
      res.redirect("/register");
      return;
    }
    const { note } = req.body;
    if (!note) {
      res.json({ success: false, error: "Note missing" });
      return;
    }
    if (typeof note !== "string") {
      res.json({ success: false, error: "Note not a string" });
      return;
    }
    const connection = await pool.getConnection();
    const userIds = await connection.query(
      "SELECT id FROM users WHERE username = ?",
      [token.username]
    );
    if (userIds.length === 0) {
      res.redirect("/register");
      return;
    }
    const userId = userIds[0].id;
    await connection.query(
      "INSERT INTO notes (user_id, content) VALUES (?, ?)",
      [userId, note]
    );
    res.redirect("/");
  });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.json({ success: false, error: "Username or password missing" });
    return;
  }
  if (typeof username !== "string" || typeof password !== "string") {
    res.json({ success: false, error: "Username or password not a string" });
    return;
  }
  const connection = await pool.getConnection();
  const result = await connection.query(
    "SELECT * FROM users WHERE username = ?",
    [username]
  );
  if (result.length > 0) {
    res.json({ success: false, error: "Username already exists" });
    return;
  }
  await connection.query(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, password]
  );
  res.cookie("jwt", jwt.sign({ username }, key), { httpOnly: true });
  res.redirect("/");
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
