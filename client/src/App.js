import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast, ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './App.css';
import { SHA256 } from 'crypto-js';
import base64url from 'base64url';

const BACKEND_URL = 'http://localhost:3001';
axios.defaults.withCredentials = true;
// Helper function to convert base64url to ArrayBuffer
const base64urlToArrayBuffer = (base64url) => {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};

// Helper function to convert ArrayBuffer to base64url
const arrayBufferToBase64url = (buffer) => {
  const base64 = btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};


function App() {
  const [registerUsername, setRegisterUsername] = useState('');
  const [loginUsername, setLoginUsername] = useState('');
  const [currentUser, setCurrentUser] = useState(null);
  const [userCredentials, setUserCredentials] = useState([]);

  useEffect(() => {
    checkCurrentUser();
  }, []);

  useEffect(() => {
    if (currentUser) {
      fetchUserCredentials();
    }
  }, [currentUser]);

  const checkCurrentUser = async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/user`, { withCredentials: true });
      setCurrentUser(response.data.username);
    } catch (error) {
      console.error('Error checking current user:', error);
    }
  };

  const fetchUserCredentials = async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/user-credentials`, { withCredentials: true });
      setUserCredentials(response.data);
    } catch (error) {
      console.error('Error fetching user credentials:', error);
    }
  };

  const register = async () => {
    try {
      const response = await axios.post(`${BACKEND_URL}/register`, { username: registerUsername });
      const { options, isNewUser } = response.data;

      options.challenge = base64urlToArrayBuffer(options.challenge);
      options.user.id = base64urlToArrayBuffer(options.user.id);

      const credential = await navigator.credentials.create({ publicKey: options });

      const attestationResponse = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        response: {
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
          attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
        },
        type: credential.type,
      };

      await axios.post(`${BACKEND_URL}/register-verify`, attestationResponse, { withCredentials: true });
      toast.success(isNewUser ? 'Registration successful' : 'New credential added successfully');
      checkCurrentUser();
    } catch (error) {
      console.error('Error during registration:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Registration failed';
      toast.error(`Registration failed: ${errorMessage}`);
    }
  };

  const login = async () => {
    try {
      const response = await axios.post(`${BACKEND_URL}/login`, { username: loginUsername });
      const publicKey = response.data;

      publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);
      publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
        ...cred,
        id: base64urlToArrayBuffer(cred.id),
      }));

      const credential = await navigator.credentials.get({ publicKey });

      const assertionResponse = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        response: {
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
          authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
          signature: arrayBufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? arrayBufferToBase64url(credential.response.userHandle) : null,
        },
        type: credential.type,
      };

      await axios.post(`${BACKEND_URL}/login-verify`, { ...assertionResponse, username: loginUsername }, { withCredentials: true });
      toast.success('Login successful');
      checkCurrentUser();
    } catch (error) {
      console.error('Error during login:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Login failed';
      toast.error(`Login failed: ${errorMessage}`);
    }
  };

  const loginWithoutUsername = async () => {
    try {
      const response = await axios.post(`${BACKEND_URL}/login-options`);
      const publicKey = response.data;

      publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);
      if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
          ...cred,
          id: base64urlToArrayBuffer(cred.id),
        }));
      }

      const credential = await navigator.credentials.get({ publicKey });

      const assertionResponse = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        response: {
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
          authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
          signature: arrayBufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? arrayBufferToBase64url(credential.response.userHandle) : null,
        },
        type: credential.type,
      };

      const verifyResponse = await axios.post(`${BACKEND_URL}/login-verify-without-username`, assertionResponse, { withCredentials: true });
      setCurrentUser(verifyResponse.data.username);
      toast.success('Login successful');
    } catch (error) {
      console.error('Error during login without username:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Login failed';
      toast.error(`Login failed: ${errorMessage}`);
    }
  };

  const logout = async () => {
    try {
      await axios.post(`${BACKEND_URL}/logout`, {}, { withCredentials: true });
      setCurrentUser(null);
      setUserCredentials([]);
      toast.success('Logout successful');
    } catch (error) {
      console.error('Error during logout:', error);
      toast.error('Logout failed');
    }
  };

  return (
    <div className="App">
      <h1>Passkey Authentication Demo</h1>
      <ToastContainer />
      {currentUser ? (
        <div className="logged-in">
          <h2>Welcome, {currentUser}!</h2>
          <button onClick={logout}>Logout</button>
          <h3>Your Credentials</h3>
          <table className="credentials-table">
            <thead>
              <tr>
                <th>Credential ID</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {userCredentials.map((cred) => (
                <tr key={cred.id}>
                  <td>{cred.credential_id.substr(0, 16)}...</td>
                  <td>{new Date(cred.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="auth-container">
          <div className="auth-step">
            <h2>Step 1: Registration</h2>
            <p className="explanation">
              When you register, we'll create a unique passkey for your account. This passkey is a secure, 
              passwordless way to log in. Your device will store this passkey securely, and our server will 
              remember a part of it. This process creates a strong, phishing-resistant authentication method 
              that's easier and safer than traditional passwords.
            </p>
            <input
              type="text"
              value={registerUsername}
              onChange={(e) => setRegisterUsername(e.target.value)}
              placeholder="Choose a username"
            />
            <button onClick={register}>Register</button>
          </div>

          <div className="auth-step">
            <h2>Step 2: Login</h2>
            <div className="login-option">
              <h3>Option A: Login with Username</h3>
              <p className="explanation">
                If you remember your username, enter it here. Your device will then prompt you to verify 
                your identity using your passkey. This might involve using your fingerprint, face recognition, 
                or a PIN, depending on your device's capabilities. By confirming your identity, you're using 
                your passkey to securely log in without needing a password.
              </p>
              <input
                type="text"
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
                placeholder="Enter your username"
              />
              <button onClick={login}>Login with Username</button>
            </div>

            <div className="login-option">
              <h3>Option B: Login without Username</h3>
              <p className="explanation">
                If you don't remember your username, no worries. Click this button, and your device will 
                show you a list of passkeys associated with this website. Select the one you want to use, 
                then verify your identity as prompted. This method allows you to log in securely even if 
                you've forgotten your username, as long as you're using a device where you've previously 
                set up a passkey for this site.
              </p>
              <button onClick={loginWithoutUsername}>Login without Username</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
