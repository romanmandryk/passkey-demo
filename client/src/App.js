import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import SHA256 from 'crypto-js/sha256';

const BACKEND_URL = 'http://localhost:3001'; // Change this to your backend URL

function App() {
  const [username, setUsername] = useState('');
  const [currentUser, setCurrentUser] = useState(null);

  useEffect(() => {
    checkUser();
  }, []);


  const checkUser = async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/user`);
      setCurrentUser(response.data.username);
    } catch (error) {
      console.error('Error checking user:', error);
    }
  };

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

  const register = async () => {
    try {
      const response = await axios.post(`${BACKEND_URL}/register`, { username });
      const publicKey = response.data;

      // Convert challenge to ArrayBuffer
      publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);

      // Generate a 32-byte buffer from the username
      const userIdHash = SHA256(username).toString();
      const userIdBuffer = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        userIdBuffer[i] = parseInt(userIdHash.substr(i * 2, 2), 16);
      }
      publicKey.user.id = userIdBuffer;

      const credential = await navigator.credentials.create({ publicKey });

      const attestationResponse = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        response: {
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
          attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
        },
        type: credential.type,
      };

      await axios.post(`${BACKEND_URL}/register-verify`, { ...attestationResponse, username });
      toast.success('Registration successful');
    } catch (error) {
      console.error('Error during registration:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Registration failed';
      toast.error(`Registration failed: ${errorMessage}`);
    }
  };

  const login = async () => {
    try {
      const response = await axios.post(`${BACKEND_URL}/login`, { username });
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

      await axios.post(`${BACKEND_URL}/login-verify`, { ...assertionResponse, username });
      toast.success('Login successful');
      checkUser();
    } catch (error) {
      console.error('Error during login:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Login failed';
      toast.error(`Login failed: ${errorMessage}`);
    }
  };

  const logout = async () => {
    try {
      await axios.post(`${BACKEND_URL}/logout`);
      setCurrentUser(null);
      toast.success('Logout successful');
    } catch (error) {
      console.error('Error during logout:', error);
      toast.error('Logout failed');
    }
  };

  return (
    <div className="App">
      <ToastContainer position="top-right" autoClose={5000} hideProgressBar={false} />
      <h1>Passkey Demo</h1>
      {currentUser ? (
        <div>
          <p>Logged in as: {currentUser}</p>
          <button onClick={logout}>Logout</button>
        </div>
      ) : (
        <div>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username"
          />
          <button onClick={register}>Register</button>
          <button onClick={login}>Login</button>
        </div>
      )}
    </div>
  );
}

export default App;
