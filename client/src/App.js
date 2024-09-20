import React, { useState, useEffect, useMemo, useCallback } from 'react';
import axios from 'axios';
import { toast, ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { useTable, useSortBy, usePagination } from 'react-table';
import { FaTrash, FaCheck } from 'react-icons/fa';
import Modal from './Modal';
import './App.css';

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
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [credentialToDelete, setCredentialToDelete] = useState(null);
  const [webAuthnSupported, setWebAuthnSupported] = useState(false);
  const [ethereumWallets, setEthereumWallets] = useState([]);
  const [newWallet, setNewWallet] = useState({ address: '', privateKey: '', alias: '' });
  const [isAddWalletModalOpen, setIsAddWalletModalOpen] = useState(false);

  const checkCurrentUser = useCallback(async () => {
    try {
      const response = await axios.get(`${BACKEND_URL}/user`);
      if (response.data && response.data.username) {
        setCurrentUser(response.data.username);
      } else {
        setCurrentUser(null);
      }
    } catch (error) {
      if (error.response && error.response.status === 401) {
        // User is not logged in, this is expected
        setCurrentUser(null);
      } else {
        // Log other unexpected errors
        console.error('Error checking current user:', error);
      }
    }
  }, []);

  useEffect(() => {
    checkCurrentUser();
  }, [checkCurrentUser]);

  useEffect(() => {
    setWebAuthnSupported(!!window.PublicKeyCredential);
  }, []);

  const fetchUserCredentials = useCallback(async () => {
    if (!currentUser) return;
    try {
      const response = await axios.get(`${BACKEND_URL}/user-credentials`);
      setUserCredentials(response.data);
    } catch (error) {
      console.error('Error fetching user credentials:', error);
    }
  }, [currentUser]);

  useEffect(() => {
    fetchUserCredentials();
  }, [fetchUserCredentials]);

  const openDeleteModal = useCallback((credentialId) => {
    setCredentialToDelete(credentialId);
    setIsModalOpen(true);
  }, []);

  const closeDeleteModal = useCallback(() => {
    setIsModalOpen(false);
    setCredentialToDelete(null);
  }, []);

  const confirmDelete = useCallback(async () => {
    if (credentialToDelete) {
      try {
        await axios.delete(`${BACKEND_URL}/credential/${credentialToDelete}`);
        toast.success('Credential deleted successfully');
        fetchUserCredentials();
      } catch (error) {
        console.error('Error deleting credential:', error);
        toast.error('Failed to delete credential');
      }
    }
    closeDeleteModal();
  }, [credentialToDelete, closeDeleteModal, fetchUserCredentials]);

  const columns = useMemo(
    () => [
      {
        Header: 'Credential ID',
        accessor: 'credential_id',
        Cell: ({ value }) => <span title={value}>{value.substr(0, 8)}...</span>
      },
      {
        Header: 'Authenticator',
        accessor: 'authenticator_model',
      },
      {
        Header: 'Device',
        accessor: 'device_info',
        Cell: ({ value }) => (
          <div className="device-info" title={value}>
            {value.split(' ').slice(0, 3).join(' ')}...
          </div>
        )
      },
      {
        Header: 'Last Used IP',
        accessor: 'last_used_ip',
      },
      {
        Header: 'Last used at',
        accessor: 'last_used_at',
        Cell: ({ value }) => new Date(value).toLocaleString()
      },
      {
        Header: 'Action',
        Cell: ({ row }) => (
          <button onClick={() => openDeleteModal(row.original.credential_id)} className="delete-btn">
            <FaTrash />
          </button>
        )
      }
    ],
    [openDeleteModal]
  );

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    prepareRow,
    page,
    canPreviousPage,
    canNextPage,
    pageOptions,
    pageCount,
    gotoPage,
    nextPage,
    previousPage,
    setPageSize,
    state: { pageIndex, pageSize },
  } = useTable(
    {
      columns,
      data: userCredentials,
      initialState: { pageIndex: 0, pageSize: 5 },
    },
    useSortBy,
    usePagination
  );

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

      await axios.post(`${BACKEND_URL}/register-verify`, attestationResponse);
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

      await axios.post(`${BACKEND_URL}/login-verify`, { ...assertionResponse, username: loginUsername });
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

      const verifyResponse = await axios.post(`${BACKEND_URL}/login-verify-without-username`, assertionResponse);
      setCurrentUser(verifyResponse.data.username);
      toast.success('Login successful');
      checkCurrentUser();
    } catch (error) {
      console.error('Error during login without username:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Login failed';
      toast.error(`Login failed: ${errorMessage}`);
    }
  };

  const logout = async () => {
    try {
      await axios.post(`${BACKEND_URL}/logout`);
      setCurrentUser(null);
      setUserCredentials([]);
      toast.success('Logout successful');
    } catch (error) {
      console.error('Error during logout:', error);
      toast.error('Logout failed');
    }
  };

  const fetchEthereumWallets = useCallback(async () => {
    if (!currentUser) return;
    try {
      const response = await axios.get(`${BACKEND_URL}/ethereum-wallets`);
      setEthereumWallets(response.data);
    } catch (error) {
      console.error('Error fetching Ethereum wallets:', error);
    }
  }, [currentUser]);

  useEffect(() => {
    fetchEthereumWallets();
  }, [fetchEthereumWallets]);

  const addEthereumWallet = async () => {
    try {
      await axios.post(`${BACKEND_URL}/add-ethereum-wallet`, newWallet);
      toast.success('Ethereum wallet added successfully');
      setIsAddWalletModalOpen(false);
      setNewWallet({ address: '', privateKey: '', alias: '' });
      fetchEthereumWallets();
    } catch (error) {
      console.error('Error adding Ethereum wallet:', error);
      toast.error('Failed to add Ethereum wallet');
    }
  };

  const deleteEthereumWallet = async (walletId) => {
    try {
      await axios.delete(`${BACKEND_URL}/ethereum-wallet/${walletId}`);
      toast.success('Ethereum wallet deleted successfully');
      fetchEthereumWallets();
    } catch (error) {
      console.error('Error deleting Ethereum wallet:', error);
      toast.error('Failed to delete Ethereum wallet');
    }
  };

  const verifyEthereumWallet = async (walletId) => {
    try {
      const response = await axios.post(`${BACKEND_URL}/verify-ethereum-wallet`, { walletId });
      if (response.data.verified) {
        toast.success('Ethereum wallet verified successfully');
        setEthereumWallets(prevWallets => 
          prevWallets.map(wallet => 
            wallet.id === walletId ? { ...wallet, is_verified: true } : wallet
          )
        );
      } else {
        toast.error('Ethereum wallet verification failed');
      }
    } catch (error) {
      console.error('Error verifying Ethereum wallet:', error);
      toast.error('Failed to verify Ethereum wallet');
    }
  };

  const ethereumWalletColumns = useMemo(
    () => [
      {
        Header: 'Address',
        accessor: 'address',
        Cell: ({ value }) => <span title={value}>{value.substr(0, 10)}...</span>
      },
      {
        Header: 'Alias',
        accessor: 'alias',
      },
      {
        Header: 'Verified',
        accessor: 'is_verified',
        Cell: ({ value }) => (value ? '✅' : '❌')
      },
      {
        Header: 'Actions',
        Cell: ({ row }) => (
          <>
            {!row.original.is_verified && (
              <button onClick={() => verifyEthereumWallet(row.original.id)} className="verify-btn">
                <FaCheck />
              </button>
            )}
            <button onClick={() => deleteEthereumWallet(row.original.id)} className="delete-btn">
              <FaTrash />
            </button>
          </>
        )
      }
    ],
    []
  );

  const {
    getTableProps: getEthereumTableProps,
    getTableBodyProps: getEthereumTableBodyProps,
    headerGroups: ethereumHeaderGroups,
    prepareRow: prepareEthereumRow,
    page: ethereumPage,
  } = useTable(
    {
      columns: ethereumWalletColumns,
      data: ethereumWallets,
      initialState: { pageIndex: 0, pageSize: 5 },
    },
    useSortBy,
    usePagination
  );

  return (
    <div className="App">
      <h1>Passkey Authentication Demo</h1>
      <ToastContainer />
      {currentUser ? (
        <div className="logged-in">
          <h2>Welcome, {currentUser}!</h2>
          <button onClick={logout}>Logout</button>
          
          {/* Ethereum Wallets Section */}
          <div className="ethereum-wallets">
            <h2>Your Ethereum Wallets</h2>
            <button onClick={() => setIsAddWalletModalOpen(true)}>Add Wallet</button>
            <div className="table-container">
              <table {...getEthereumTableProps()} className="modern-table">
                <thead>
                  {ethereumHeaderGroups.map(headerGroup => (
                    <tr {...headerGroup.getHeaderGroupProps()}>
                      {headerGroup.headers.map(column => (
                        <th {...column.getHeaderProps(column.getSortByToggleProps())}>
                          {column.render('Header')}
                          <span>
                            {column.isSorted
                              ? column.isSortedDesc
                                ? ' 🔽'
                                : ' 🔼'
                              : ''}
                          </span>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody {...getEthereumTableBodyProps()}>
                  {ethereumPage.map(row => {
                    prepareEthereumRow(row);
                    return (
                      <tr {...row.getRowProps()}>
                        {row.cells.map(cell => (
                          <td {...cell.getCellProps()}>{cell.render('Cell')}</td>
                        ))}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Existing Passkeys Section */}
          <div className="credentials-table">
            <h2>Your Passkeys</h2>
            <div className="table-container">
              <table {...getTableProps()} className="modern-table">
                <thead>
                  {headerGroups.map(headerGroup => (
                    <tr {...headerGroup.getHeaderGroupProps()}>
                      {headerGroup.headers.map(column => (
                        <th {...column.getHeaderProps(column.getSortByToggleProps())}>
                          {column.render('Header')}
                          <span>
                            {column.isSorted
                              ? column.isSortedDesc
                                ? ' 🔽'
                                : ' 🔼'
                              : ''}
                          </span>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody {...getTableBodyProps()}>
                  {page.map(row => {
                    prepareRow(row);
                    return (
                      <tr {...row.getRowProps()}>
                        {row.cells.map(cell => (
                          <td {...cell.getCellProps()}>{cell.render('Cell')}</td>
                        ))}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="pagination">
              <button onClick={() => gotoPage(0)} disabled={!canPreviousPage}>
                {'<<'}
              </button>{' '}
              <button onClick={() => previousPage()} disabled={!canPreviousPage}>
                {'<'}
              </button>{' '}
              <button onClick={() => nextPage()} disabled={!canNextPage}>
                {'>'}
              </button>{' '}
              <button onClick={() => gotoPage(pageCount - 1)} disabled={!canNextPage}>
                {'>>'}
              </button>{' '}
              <span>
                Page{' '}
                <strong>
                  {pageIndex + 1} of {pageOptions.length}
                </strong>{' '}
              </span>
              <span>
                | Go to page:{' '}
                <input
                  type="number"
                  defaultValue={pageIndex + 1}
                  onChange={e => {
                    const page = e.target.value ? Number(e.target.value) - 1 : 0
                    gotoPage(page)
                  }}
                  style={{ width: '50px' }}
                />
              </span>{' '}
              <select
                value={pageSize}
                onChange={e => {
                  setPageSize(Number(e.target.value))
                }}
              >
                {[5, 10, 20].map(pageSize => (
                  <option key={pageSize} value={pageSize}>
                    Show {pageSize}
                  </option>
                ))}
              </select>
            </div>
          </div>
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
      <Modal
        isOpen={isModalOpen}
        onClose={closeDeleteModal}
        onConfirm={confirmDelete}
        title="Confirm Deletion"
        message="Are you sure you want to delete this passkey? This will remove the passkey from the server, but it will still be kept in your passkey manager. You may need to remove it manually from your device if you no longer wish to use it."
      />

      {/* New Modal for adding Ethereum wallets */}
      <Modal
        isOpen={isAddWalletModalOpen}
        onClose={() => setIsAddWalletModalOpen(false)}
        onConfirm={addEthereumWallet}
        title="Add Ethereum Wallet"
        message={
          <div>
            <input
              type="text"
              placeholder="Address"
              value={newWallet.address}
              onChange={(e) => setNewWallet({ ...newWallet, address: e.target.value })}
            />
            <input
              type="password"
              placeholder="Private Key"
              value={newWallet.privateKey}
              onChange={(e) => setNewWallet({ ...newWallet, privateKey: e.target.value })}
            />
            <input
              type="text"
              placeholder="Alias (optional)"
              value={newWallet.alias}
              onChange={(e) => setNewWallet({ ...newWallet, alias: e.target.value })}
            />
          </div>
        }
      />
    </div>
  );
}

export default App;
