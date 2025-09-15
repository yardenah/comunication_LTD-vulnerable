export const API_URL = "/api";

// Login user 
export async function loginUser(username, password) {
  const res = await fetch(`${API_URL}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  const data = await res.json();

  if (!res.ok) {
    // Handle both string and object error responses
    const errorMessage = typeof data === 'string' ? data : (data.message || "Login failed");
    throw new Error(errorMessage);
  }

  return data; 
}

// Register user 
export async function registerUser(userData) {
  const res = await fetch(`${API_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(userData),
  });

  const data = await res.json();

  if (!res.ok) {
    // Handle both string and object error responses
    const errorMessage = typeof data === 'string' ? data : (data.message || "Something went wrong");
    throw new Error(errorMessage);
  }

  return data;
}


// Change password
export async function changePassword(username,oldPassword, newPassword) {
  const res = await fetch(`${API_URL}/change-password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username,oldPassword, newPassword }),
  });

  const data = await res.json();
  if (!res.ok) {
    // Handle both string and object error responses
    const errorMessage = typeof data === 'string' ? data : (data.message || 'Something went wrong');
    throw new Error(errorMessage);
  }

  return data;
}

// Request reset password
export async function requestPasswordReset(username) {
  const res = await fetch(`${API_URL}/request-reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  });

  const data = await res.json();
  if (!res.ok) {
    // Handle both string and object error responses
    const errorMessage = typeof data === 'string' ? data : (data.message || 'Failed to send reset token');
    throw new Error(errorMessage);
  }
  return data;
}

// Reset password
export async function resetPassword({ username, token, newPassword }) {
  const res = await fetch(`${API_URL}/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, token, newPassword }),
  });

  const data = await res.json();
  if (!res.ok) {
    // Handle both string and object error responses
    const errorMessage = typeof data === 'string' ? data : (data.message || 'Failed to reset password');
    throw new Error(errorMessage);
  }
  return data;
}

// Get password configuration
export async function getPasswordConfig() {
  const res = await fetch(`${API_URL}/config`);
  if (!res.ok) {
    throw new Error("Failed to fetch password configuration");
  }
  return await res.json();
}

// Get all clients
export async function getClients() {
  const res = await fetch(`${API_URL}/clients`);
  if (!res.ok) {
    throw new Error("Failed to fetch clients");
  }
  return await res.json();
}

// Add new client
export async function addClient(clientData) {
  const res = await fetch(`${API_URL}/clients`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(clientData),
  });

  if (!res.ok) {
    throw new Error("Failed to add client");
  }
  return await res.json();
}


