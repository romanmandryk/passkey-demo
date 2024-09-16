const express = require('express');
const cors = require('cors');
const session = require('express-session');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const base64url = require('base64url');
const { initDB, getUser, saveUser, updateUserChallenge, getAllUsers } = require('./db');

const app = express();

// CORS middleware should come first
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));

// Body parsing middleware should come before session middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
  secret: 'your-secret-key', // Replace with a strong, unique secret
  resave: false,
  saveUninitialized: false,
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
initDB().then(() => {});

app.post('/register', async (req, res, next) => {
  try {
    const username = req.body.username;
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const existingUser = await getUser(username);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: username,
      attestationType: 'none',
    });

    await saveUser(username, { currentChallenge: options.challenge });

    res.json(options);
  } catch (error) {
    next(error);
  }
});

app.post('/register-verify', async (req, res, next) => {
  const username = req.body.username;
  const user = await getUser(username);

  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  try {
    const userCredential = JSON.parse(user.credential);
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: userCredential.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      await saveUser(username, verification.registrationInfo);
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

  if (!user || !user.credential) {
    return res.status(400).json({ error: 'User not found or not registered' });
  }

  const userCredential = JSON.parse(user.credential);

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [{
      id: userCredential.credentialID,
      type: 'public-key',
    }],
  });

  await updateUserChallenge(username, options.challenge);

  res.json(options);
});

app.post('/login-verify', async (req, res) => {
  const username = req.body.username;
  const user = await getUser(username);

  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  try {
    const userCredential = JSON.parse(user.credential);
    
    // Ensure the credentialID is in the correct format
    if (typeof userCredential.credentialID === 'string') {
      userCredential.credentialID = base64url.toBuffer(userCredential.credentialID);
    }

    // Ensure the credentialPublicKey is in the correct format
    if (typeof userCredential.credentialPublicKey === 'string') {
      userCredential.credentialPublicKey = base64url.toBuffer(userCredential.credentialPublicKey);
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: userCredential.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: userCredential,
    });

    if (verification.verified) {
      req.session.currentUser = username;
      req.session.save(err => {
        if (err) {
          console.error('Error saving session:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        res.json({ success: true });
      });
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
      // Don't specify allowCredentials to allow selection from all registered credentials
    });

    // Store the challenge for all users
    const users = await getAllUsers();
    for (const user of users) {
      await updateUserChallenge(user.username, options.challenge);
    }

    res.json(options);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/login-verify-without-username', async (req, res) => {
  try {
    const { id, rawId, response, type } = req.body;

    // Find the user based on the credential ID
    let foundUser = null;
    let foundCredential = null;
    const users = await getAllUsers();
    for (const user of users) {
      const userCredential = JSON.parse(user.credential);
      if (userCredential.credentialID === rawId) {
        foundUser = user;
        foundCredential = userCredential;
        break;
      }
    }

    if (!foundUser || !foundCredential) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Ensure the credentialID and credentialPublicKey are in the correct format
    if (typeof foundCredential.credentialID === 'string') {
      foundCredential.credentialID = base64url.toBuffer(foundCredential.credentialID);
    }
    if (typeof foundCredential.credentialPublicKey === 'string') {
      foundCredential.credentialPublicKey = base64url.toBuffer(foundCredential.credentialPublicKey);
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: foundCredential.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: foundCredential,
    });

    if (verification.verified) {
      req.session.currentUser = foundUser.username;
      req.session.save(err => {
        if (err) {
          console.error('Error saving session:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        res.json({ success: true, username: foundUser.username });
      });
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

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
