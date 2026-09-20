/* ----------------------------------------------------
   Net‑Scan backend – Node / Express / MySQL
---------------------------------------------------- */

const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const path = require('path');

const app = express();
app.use(bodyParser.json()); // JSON bodies for API
app.use(express.static(path.join(__dirname, '..'))); // serve static assets

// ------------------------------------------------------------------
// 1. MySQL connection helper
async function connectDB() {
  const cfg = require('./config/connection.json');
  return mysql.createConnection(cfg);
}
// ------------------------------------------------------------------
// 2. Create tables if they don’t exist yet
connectDB()
  .then(async cnx => {
    await cnx.query(`CREATE DATABASE IF NOT EXISTS netscan`);
    await cnx.query(`USE netscan`);

    // users
    await cnx.query(`
      CREATE TABLE IF NOT EXISTS users(
         id INT AUTO_INCREMENT PRIMARY KEY,
         username VARCHAR(50) UNIQUE,
         password_hash CHAR(255),
         role ENUM('admin','viewer') DEFAULT 'admin'
      )`);
    // scans
    await cnx.query(`
      CREATE TABLE IF NOT EXISTS scans(
         id INT AUTO_INCREMENT PRIMARY KEY,
         scan_name VARCHAR(100),
         start_time DATETIME DEFAULT CURRENT_TIMESTAMP
      )`);
    // permissions
    await cnx.query(`
      CREATE TABLE IF NOT EXISTS permissions(
         user_id  INT,
         scan_id  INT,
         can_read BOOLEAN DEFAULT TRUE,
         can_write BOOLEAN DEFAULT FALSE,
         PRIMARY KEY(user_id,scan_id),
         FOREIGN KEY(user_id) REFERENCES users(id),
         FOREIGN KEY(scan_id) REFERENCES scans(id)
      )`);
    console.log('DB schema ready');
  })
  .catch(console.error);
// ------------------------------------------------------------------
// 3. API – list all scans
app.get('/api/scans', async (req,res)=>{
  const cnx = await connectDB();
  const rows = await cnx.query('SELECT * FROM scans');
  res.json(rows);
}),

app.post('/api/scans', async (req,res)=>{ 
  const cnx=await connectDB(); 
  await cnx.query('INSERT INTO scans(scan_name) VALUES(?)',[req.body.name]); 
  res.json({status:'ok'}); 
});
// ------------------------------------------------------------------
// 4. API – admin login (creates user + hash)
app.post('/admin/login', async (req,res)=>{
  const { username, password }   = req.body;    // body: {username,password}
  const pwdHash = require('bcryptjs').hashSync(password,10);        // bcrypt
  const cnx     = await connectDB();
  await cnx.query(
     'INSERT INTO users(username,password_hash) VALUES(?,?)',
     [ username , pwdHash ]
  );
  res.json({ status:'ok' });
});
// ------------------------------------------------------------------
// 5. Start listening
app.get('/api/users', async (req,res)=>{
  const cnx = await connectDB();
  const rows = await cnx.query('SELECT * FROM users');
  res.json(rows);
});

app.listen(3000,()=>console.log('Net‑Scan backend running on :3000'));
