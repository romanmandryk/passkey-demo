# Passkey Authentication Demo

This project demonstrates a basic implementation of passkey-based authentication using a Node.js backend and a React frontend. It allows users to register, login, and logout using passkeys (WebAuthn).

![Screenshot of the Passkey Demo](client/public/screen.png)

## Project Structure

- `/server`: Contains the Node.js backend code
- `/client`: Contains the React frontend code

## Features

- User registration with passkeys
- User login with passkeys (with or without username)
- User logout
- Display of currently logged-in user
- Modern, user-friendly interface with explanations of the passkey process

## Prerequisites

- Node.js (v18 or later recommended)
- npm (comes with Node.js)

## Installation

### Server Setup

1. Navigate to the server directory:
   ```
   cd server
   ```

2. Install dependencies:
   ```
   npm install
   ```

### Client Setup

1. Navigate to the client directory:
   ```
   cd client
   ```

2. Install dependencies:
   ```
   npm install
   ```

## Running the Application

### Start the Server

1. From the root directory, navigate to the server folder:
   ```
   cd server
   ```

2. Start the server:
   ```
   node app.js
   ```

   The server will start running on `http://localhost:3001`.

### Start the Client

1. Open a new terminal window/tab
2. From the root directory, navigate to the client folder:
   ```
   cd client
   ```

3. Start the React development server:
   ```
   npm start
   ```

   The client will start running on `http://localhost:3000`.

## Usage

1. Open your web browser and go to `http://localhost:3000`
2. Use the interface to register a new user with a passkey
3. Log in using the registered passkey (with or without username)
4. Log out when finished

## Note

This is a demonstration project and should not be used in production without further security enhancements and thorough testing.

## License

[MIT License](LICENSE)
