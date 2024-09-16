const sqlite3 = require('sqlite3').verbose();
const base64url = require('base64url');

let db;

function initDB() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database('./users.db', (err) => {
      if (err) {
        console.error('Error creating database', err);
        reject(err);
      } else {
        console.log('Database opened');
        db.serialize(() => {
          db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE
          )`);
          db.run(`CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            credential_id TEXT UNIQUE,
            public_key TEXT,
            counter INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
          )`);
          resolve();
        });
      }
    });
  });
}

function runQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function getUser(username) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

async function createUser(username) {
  const result = await runQuery('INSERT INTO users (username) VALUES (?)', [username]);
  return result.lastID;
}

async function addCredential(userId, credential) {
  const credentialToStore = {
    credentialID: credential.credentialID instanceof Buffer || credential.credentialID instanceof Uint8Array
      ? base64url.encode(credential.credentialID) 
      : credential.credentialID,
    credentialPublicKey: credential.credentialPublicKey instanceof Buffer || credential.credentialPublicKey instanceof Uint8Array
      ? base64url.encode(credential.credentialPublicKey) 
      : credential.credentialPublicKey,
  };

  await runQuery(
    'INSERT INTO credentials (user_id, credential_id, public_key, counter) VALUES (?, ?, ?, ?)',
    [userId, credentialToStore.credentialID, credentialToStore.credentialPublicKey, credential.counter || 0]
  );
}

function getUserCredentials(userId) {
  return new Promise((resolve, reject) => {
    db.all('SELECT * FROM credentials WHERE user_id = ?', [userId], (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function getAllUsers() {
  return new Promise((resolve, reject) => {
    db.all('SELECT * FROM users', (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

module.exports = {
  initDB,
  getUser,
  createUser,
  addCredential,
  getUserCredentials,
  getAllUsers
};
