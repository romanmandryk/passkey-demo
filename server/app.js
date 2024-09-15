const express = require('express');
const cors = require('cors');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const base64url = require('base64url');
const { isoUint8Array } = require('@simplewebauthn/server/helpers');

const app = express();
app.use(cors());
app.use(express.json());

const rpName = 'Passkey Demo';
const rpID = 'localhost';
const origin = `http://${rpID}:3000`;

const users = new Map();
let currentUser = null;

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.post('/register', async (req, res, next) => {
  try {
    const username = req.body.username;
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    if (users.has(username)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    //const userId = isoUint8Array.fromUTF8String(base64url.encode(username));
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      //userID: userId,
      userName: username,
      attestationType: 'none',
    });

    users.set(username, { currentChallenge: options.challenge });
    res.json(options);
  } catch (error) {
    next(error);
  }
});

app.post('/register-verify', async (req, res, next) => {
  const username = req.body.username;
  const user = users.get(username);

  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      user.credential = verification.registrationInfo;
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
  const user = users.get(username);

  if (!user || !user.credential) {
    return res.status(400).json({ error: 'User not found or not registered' });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [{
      id: user.credential.credentialID,
      type: 'public-key',
    }],
  });

  user.currentChallenge = options.challenge;
  res.json(options);
});

app.post('/login-verify', async (req, res) => {
  const username = req.body.username;
  const user = users.get(username);

  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: user.credential,
    });

    if (verification.verified) {
      currentUser = username;
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Authentication failed' });
    }
  } catch (error) {
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
    for (const user of users.values()) {
      user.currentChallenge = options.challenge;
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
    for (const [username, user] of users.entries()) {
      if (user.credential && user.credential.credentialID === rawId) {
        foundUser = { ...user, username };
        foundCredential = user.credential;
        break;
      }
    }

    if (!foundUser || !foundCredential) {
      return res.status(400).json({ error: 'User not found' });
    }

    const verification = await verifyAuthenticationResponse({
      response: {
        id,
        rawId,
        response,
        type,
      },
      expectedChallenge: foundUser.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: foundCredential,
    });

    if (verification.verified) {
      currentUser = foundUser.username;
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
  currentUser = null;
  res.json({ success: true });
});

app.get('/user', (req, res) => {
  if (currentUser) {
    res.json({ username: currentUser });
  } else {
    res.status(401).json({ error: 'Not logged in' });
  }
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
