require('dotenv').config();

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const base64url = require('base64url');
const { initDB, getUser, createUser, addCredential, getUserCredentials, getAllUsers, updateCredentialUsage, deleteCredential, addEthereumWallet, getEthereumWallets, deleteEthereumWallet, verifyEthereumWallet } = require('./db');
const { ethers } = require('ethers');
const crypto = require('crypto');

const app = express();

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'your-secret-key', // Replace with a strong, unique secret
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false, // Set to true if using https
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

const rpName = 'Passkey Demo';
const rpID = 'localhost';
const origin = `http://${rpID}:3000`;

// Initialize the database
initDB().then(() => {
  
}).catch(err => {
  
});

// Load the AAGUID mapping more efficiently
const aaguidMap = require('./aaguid.json');

app.post('/register', async (req, res, next) => {
  try {
    const username = req.body.username;
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    let user = await getUser(username);
    let isNewUser = false;
    if (!user) {
      const userId = await createUser(username);
      user = { id: userId, username };
      isNewUser = true;
    }

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      //userID: user.id.toBuffer(),
      userName: username,
      attestationType: 'none',
    });

    req.session.challenge = options.challenge;
    req.session.registrationUserId = user.id;

    res.json({ options, isNewUser });
  } catch (error) {
    next(error);
  }
});

app.post('/register-verify', async (req, res, next) => {
  const userId = req.session.registrationUserId;
  if (!userId) {
    return res.status(400).json({ error: 'Registration session not found' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: req.session.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      const { aaguid } = verification.registrationInfo;
      const deviceInfo = req.headers['user-agent'] || 'Unknown device';
      const ipAddress = req.ip;
      const authenticatorModel = aaguidMap[aaguid]?.name || 'Unknown model';
      
      await addCredential(userId, verification.registrationInfo, deviceInfo, ipAddress, authenticatorModel);
      delete req.session.challenge;
      delete req.session.registrationUserId;
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Registration failed' });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/login', async (req, res) => {
  const username = req.body.username;
  const user = await getUser(username);

  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  const userCredentials = await getUserCredentials(user.id);

  if (userCredentials.length === 0) {
    return res.status(400).json({ error: 'No credentials found for this user' });
  }
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: userCredentials.map(cred => ({
      id: cred.credential_id,
      type: 'public-key',
    })),
  });

  req.session.challenge = options.challenge;
  req.session.username = username;

  res.json(options);
});

app.post('/login-verify', async (req, res) => {
  const username = req.session.username;
  const user = await getUser(username);  
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  const userCredentials = await getUserCredentials(user.id);

  if (userCredentials.length === 0) {
    return res.status(400).json({ error: 'No credentials found for this user' });
  }

  try {
    const credentialId = req.body.rawId;
    const matchedCredential = userCredentials.find(cred => cred.credential_id === credentialId);

    if (!matchedCredential) {
      return res.status(400).json({ error: 'No matching credential found' });
    }

    const authenticator = {
      credentialID: base64url.toBuffer(matchedCredential.credential_id),
      credentialPublicKey: base64url.toBuffer(matchedCredential.public_key),
      counter: matchedCredential.counter,
    };

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: req.session.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
    });

    if (verification.verified) {
      req.session.currentUser = username;
      delete req.session.challenge;
      delete req.session.username;
      const deviceInfo = req.headers['user-agent'] || 'Unknown device';
      await updateCredentialUsage(credentialId, req.ip, deviceInfo);
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Authentication failed' });
    }
  } catch (error) {
    console.error('Error in login-verify', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/login-options', async (req, res) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID,
    });

    req.session.challenge = options.challenge;

    res.json(options);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/login-verify-without-username', async (req, res) => {
  try {
    const { id, rawId, response, type } = req.body;
    const users = await getAllUsers();
    let foundUser = null;
    let foundCredential = null;

    for (const user of users) {
      const userCredentials = await getUserCredentials(user.id);
      foundCredential = userCredentials.find(cred => cred.credential_id === rawId);
      if (foundCredential) {
        foundUser = user;
        break;
      }
    }

    if (!foundUser || !foundCredential) {
      return res.status(400).json({ error: 'User not found' });
    }

    const authenticator = {
      credentialID: base64url.toBuffer(foundCredential.credential_id),
      credentialPublicKey: base64url.toBuffer(foundCredential.public_key),
      counter: foundCredential.counter,
    };

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: req.session.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
    });

    if (verification.verified) {
      req.session.currentUser = foundUser.username;
      delete req.session.challenge;
      
      const deviceInfo = req.headers['user-agent'] || 'Unknown device';
      await updateCredentialUsage(foundCredential.credential_id, req.ip, deviceInfo);
      
      res.json({ success: true, username: foundUser.username });
    } else {
      res.status(400).json({ error: 'Authentication failed' });
    }
  } catch (error) {
    console.error('Error in login-verify-without-username:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Could not log out, please try again' });
    }
    res.json({ success: true });
  });
});

app.get('/user', (req, res) => {
  if (req.session.currentUser) {
    res.json({ username: req.session.currentUser });
  } else {
    res.status(401).json({ error: 'Not logged in' });
  }
});

app.get('/user-credentials', async (req, res) => {
  if (!req.session.currentUser) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  try {
    const user = await getUser(req.session.currentUser);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const credentials = await getUserCredentials(user.id);
    res.json(credentials);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user credentials' });
  }
});

app.delete('/credential/:id', async (req, res) => {
  if (!req.session.currentUser) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const credentialId = req.params.id;
  try {
    const user = await getUser(req.session.currentUser);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userCredentials = await getUserCredentials(user.id);
    const credentialToDelete = userCredentials.find(cred => cred.credential_id === credentialId);

    if (!credentialToDelete) {
      return res.status(403).json({ error: 'You do not have permission to delete this credential' });
    }

    await deleteCredential(credentialId);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete credential' });
  }
});

// Add this function to encrypt the private key
function encryptPrivateKey(privateKey, encryptionKey) {
  // Ensure the encryption key is 32 bytes long
  const key = crypto.createHash('sha256').update(String(encryptionKey)).digest('base64').substr(0, 32);
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(privateKey);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Add this function to decrypt the private key
function decryptPrivateKey(encryptedPrivateKey, encryptionKey) {
  // Ensure the encryption key is 32 bytes long
  const key = crypto.createHash('sha256').update(String(encryptionKey)).digest('base64').substr(0, 32);
  
  const textParts = encryptedPrivateKey.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Add a new Ethereum wallet
app.post('/add-ethereum-wallet', async (req, res) => {
  if (!req.session.currentUser) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const { address, privateKey, alias } = req.body;
  const encryptionKey = process.env.ENCRYPTION_KEY;

  if (!encryptionKey) {
    console.error('ENCRYPTION_KEY is not set in the environment variables');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  try {
    const user = await getUser(req.session.currentUser);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const encryptedPrivateKey = encryptPrivateKey(privateKey, encryptionKey);
    await addEthereumWallet(user.id, address, encryptedPrivateKey, alias);
    res.json({ success: true });
  } catch (error) {
    console.error('Error adding Ethereum wallet:', error);
    res.status(500).json({ error: 'Failed to add Ethereum wallet', details: error.message });
  }
});

// Get Ethereum wallets for the current user
app.get('/ethereum-wallets', async (req, res) => {
  if (!req.session.currentUser) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  try {
    const user = await getUser(req.session.currentUser);
    const wallets = await getEthereumWallets(user.id);
    res.json(wallets);
  } catch (error) {
    console.error('Error fetching Ethereum wallets:', error);
    res.status(500).json({ error: 'Failed to fetch Ethereum wallets' });
  }
});

// Delete an Ethereum wallet
app.delete('/ethereum-wallet/:id', async (req, res) => {
  if (!req.session.currentUser) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const walletId = req.params.id;
  try {
    const user = await getUser(req.session.currentUser);
    await deleteEthereumWallet(user.id, walletId);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete Ethereum wallet' });
  }
});

// Verify an Ethereum wallet
app.post('/verify-ethereum-wallet', async (req, res) => {
  if (!req.session.currentUser) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const { walletId } = req.body;
  const encryptionKey = process.env.ENCRYPTION_KEY;

  if (!encryptionKey) {
    console.error('ENCRYPTION_KEY is not set in the environment variables');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  try {
    const user = await getUser(req.session.currentUser);
    const wallet = await getEthereumWallets(user.id, walletId);
    
    if (!wallet) {
      return res.status(404).json({ error: 'Wallet not found' });
    }

    if (!wallet.private_key) {
      return res.status(400).json({ error: 'Wallet private key is missing' });
    }

    const decryptedPrivateKey = decryptPrivateKey(wallet.private_key, encryptionKey);
    const ethWallet = new ethers.Wallet(decryptedPrivateKey);
    const message = "Verify wallet ownership";
    const signature = await ethWallet.signMessage(message);
    
    const recoveredAddress = ethers.verifyMessage(message, signature);

    if (recoveredAddress.toLowerCase() === wallet.address.toLowerCase()) {
      await verifyEthereumWallet(walletId);
      const updatedWallet = await getEthereumWallets(user.id, walletId);
      res.json({ success: true, verified: true, wallet: updatedWallet });
    } else {
      res.json({ success: true, verified: false });
    }
  } catch (error) {
    console.error('Error verifying Ethereum wallet:', error);
    res.status(500).json({ error: 'Failed to verify Ethereum wallet', details: error.message });
  }
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
