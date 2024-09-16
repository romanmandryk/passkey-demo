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
        db.run(`CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          credential TEXT
        )`, (err) => {
          if (err) {
            console.error('Error creating users table', err);
            reject(err);
          } else {
            resolve();
          }
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

async function saveUser(username, credential) {
  // Helper function to check if an object is a Uint8Array or Buffer
  const isUint8ArrayOrBuffer = (obj) => 
    obj instanceof Uint8Array || obj instanceof Buffer;

  // Helper function to convert Uint8Array or Buffer to base64url string
  const convertToBase64Url = (data) => 
    base64url.encode(Buffer.from(data));

  // Convert Uint8Array or Buffer objects to base64url strings for storage
  const credentialToStore = {
    ...credential,
    credentialID: isUint8ArrayOrBuffer(credential.credentialID)
      ? convertToBase64Url(credential.credentialID)
      : credential.credentialID,
    credentialPublicKey: isUint8ArrayOrBuffer(credential.credentialPublicKey)
      ? convertToBase64Url(credential.credentialPublicKey)
      : credential.credentialPublicKey,
  };

  const existingUser = await getUser(username);
  if (existingUser) {
    await runQuery('UPDATE users SET credential = ? WHERE username = ?', [JSON.stringify(credentialToStore), username]);
  } else {
    await runQuery('INSERT INTO users (username, credential) VALUES (?, ?)', [username, JSON.stringify(credentialToStore)]);
  }
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
  saveUser,
  getAllUsers
};
