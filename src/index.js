
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";

dotenv.config();

const app = express();
app.use(cors({ origin: "*" })); // tighten for prod
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

app.get("/health", async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ status: "ok", db: rows[0].ok === 1 });
  } catch (err) {
    res.status(500).json({ status: "error", error: err.message });
  }
});

app.get("/api/items", async (_req, res) => {
  const [rows] = await pool.query("SELECT id, name, price FROM items ORDER BY id DESC");
  res.json(rows);
});

app.post("/api/items", async (req, res) => {
  const { name, price } = req.body;
  if (!name || price == null) {
    return res.status(400).json({ error: "name and price are required" });
  }
  try {
    const [result] = await pool.execute(
      "INSERT INTO items (name, price) VALUES (?, ?)",
      [name, price]
    );
    res.status(201).json({ id: result.insertId, name, price });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/items/:id", async (req, res) => {
  const { id } = req.params;
  const { name, price } = req.body;
  try {
    const [result] = await pool.execute(
      "UPDATE items SET name = ?, price = ? WHERE id = ?",
      [name, price, id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: "Not found" });
    res.json({ id: Number(id), name, price });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/items/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.execute("DELETE FROM items WHERE id = ?", [id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Not found" });
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API listening on :${port}`));
