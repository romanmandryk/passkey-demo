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
            device_info TEXT,
            last_used_ip TEXT,
            last_used_at DATETIME,
            authenticator_model TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
          )`);
          db.run(`CREATE TABLE IF NOT EXISTS ethereum_wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            address TEXT,
            private_key TEXT,
            alias TEXT,
            is_verified BOOLEAN DEFAULT 0,
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

function addCredential(userId, credential, deviceInfo, ipAddress, authenticatorModel) {
  const credentialToStore = {
    credentialID: credential.credentialID instanceof Buffer || credential.credentialID instanceof Uint8Array
      ? base64url.encode(credential.credentialID) 
      : credential.credentialID,
    credentialPublicKey: credential.credentialPublicKey instanceof Buffer || credential.credentialPublicKey instanceof Uint8Array
      ? base64url.encode(credential.credentialPublicKey) 
      : credential.credentialPublicKey,
  };

  return runQuery(
    'INSERT INTO credentials (user_id, credential_id, public_key, counter, device_info, last_used_ip, authenticator_model) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [userId, credentialToStore.credentialID, credentialToStore.credentialPublicKey, credential.counter || 0, deviceInfo, ipAddress, authenticatorModel]
  );
}

function updateCredentialUsage(credentialId, ipAddress, deviceInfo) {
  return runQuery(
    'UPDATE credentials SET last_used_ip = ?, last_used_at = CURRENT_TIMESTAMP, device_info = ? WHERE credential_id = ?',
    [ipAddress, deviceInfo, credentialId]
  );
}

function deleteCredential(credentialId) {
  return runQuery('DELETE FROM credentials WHERE credential_id = ?', [credentialId]);
}

function getUserCredentials(userId) {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT credential_id, public_key, counter, device_info, last_used_ip, last_used_at, authenticator_model 
       FROM credentials WHERE user_id = ?`,
      [userId],
      (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows);
        }
      }
    );
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

async function addEthereumWallet(userId, address, encryptedPrivateKey, alias) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO ethereum_wallets (user_id, address, private_key, alias) VALUES (?, ?, ?, ?)`,
      [userId, address, encryptedPrivateKey, alias],
      function (err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.lastID);
        }
      }
    );
  });
}

async function getEthereumWallets(userId, walletId = null) {
  return new Promise((resolve, reject) => {
    if (walletId) {
      db.get('SELECT * FROM ethereum_wallets WHERE user_id = ? AND id = ?', [userId, walletId], (err, row) => {
        if (err) reject(err);
        else if (!row) reject(new Error('Wallet not found'));
        else resolve(row);
      });
    } else {
      db.all('SELECT * FROM ethereum_wallets WHERE user_id = ?', [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    }
  });
}

async function deleteEthereumWallet(userId, walletId) {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM ethereum_wallets WHERE user_id = ? AND id = ?', [userId, walletId], function(err) {
      if (err) reject(err);
      else resolve(this.changes);
    });
  });
}

async function verifyEthereumWallet(walletId) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE ethereum_wallets SET is_verified = ? WHERE id = ?', [1, walletId], function(err) {
      if (err) {
        console.error('Error updating wallet verification status:', err);
        reject(err);
      } else {
        console.log(`Wallet ${walletId} verified. Rows affected: ${this.changes}`);
        resolve(this.changes);
      }
    });
  });
}

module.exports = {
  initDB,
  getUser,
  createUser,
  addCredential,
  getUserCredentials,
  getAllUsers,
  updateCredentialUsage,
  deleteCredential,
  addEthereumWallet,
  getEthereumWallets,
  deleteEthereumWallet,
  verifyEthereumWallet
};
