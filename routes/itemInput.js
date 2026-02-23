
// routes/itemInput.js
const express = require("express");
const router = express.Router();
const { pool } = require("../db");

// POST /api/itemInput
router.post("/", async (req, res) => {
  try {
    const {
      userID,
      brand,
      itemName,
      itemID,
      feature,
      quantity,
      itemCount,
      priceValue,
      channel,
      shop_name,
      shop_address
    } = req.body || {};

    if (!userID) return res.status(400).json({ error: "userID_required" });
    if (!itemName) return res.status(400).json({ error: "itemName_required" });
    if (!priceValue) return res.status(400).json({ error: "price_required" });

    const sql = `
  INSERT INTO itemInput
  (userID, brand, itemName, itemID, itemNo, feature,
   quantity, itemCount, priceValue, priceID, discountApplied,
   channel, shop_name, shop_address, chainShopID, createdAt)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

    await pool.execute(sql, [
      userID,
      brand ?? null,
      itemName,
      itemID ?? null,
      feature ?? null,
      quantity ?? null,
      itemCount ?? 1,
      priceValue,
      channel,
      shop_name ?? null,
      shop_address ?? null
    ]);

    res.status(201).json({ ok: true });
  } catch (err) {
    console.error("POST /api/itemInput error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

module.exports = router;
