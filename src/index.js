
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";

dotenv.config();

const app = express();
app.use(cors({ origin: "*" })); // tighten for production
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: process.env.MYSQL_PORT || 3306,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Health check
app.get("/health", async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ status: "ok", db: rows[0].ok === 1 });
  } catch (err) {
    res.status(500).json({ status: "error", error: err.message });
  }
});


app.post("/api/signup", async (req, res) => {
  const {
    username,
    password,
    email,
    phone_country_code,
    phone_number,
    secuQuestion1,
    secuAns1,
    secuQuestion2,
    secuAns2,
    secuQuestion3,
    secuAns3,
  } = req.body;

  if (!username && !email && !phone_number) {
    return res.status(400).json({ error: "At least one identifier is required" });
  }
  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }

  try {
    const [result] = await pool.execute(
      `INSERT INTO loginTable 
       (username, password, email, phone_country_code, phone_number, 
        secuQuestion1, secuAns1, secuQuestion2, secuAns2, secuQuestion3, secuAns3)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        username || null,
        password,
        email || null,
        phone_country_code || null,
        phone_number || null,
        secuQuestion1 || null,
        secuAns1 || null,
        secuQuestion2 || null,
        secuAns2 || null,
        secuQuestion3 || null,
        secuAns3 || null,
      ]
    );

    res.status(201).json({ userID: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API listening on :${port}`));
