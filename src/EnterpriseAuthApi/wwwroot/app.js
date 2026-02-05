const output = document.getElementById('output');
const statusEl = document.getElementById('status');
const accessExpiryEl = document.getElementById('access-expiry');
const refreshExpiryEl = document.getElementById('refresh-expiry');

let session = {
  accessToken: null,
  refreshToken: null,
  accessTokenExpiresAtUtc: null,
  refreshTokenExpiresAtUtc: null
};

function log(message, data) {
  const payload = data ? `${message}\n${JSON.stringify(data, null, 2)}` : message;
  output.textContent = `${new Date().toISOString()}\n${payload}`;
}

function updateSessionUi() {
  statusEl.textContent = session.accessToken ? 'Signed in' : 'Signed out';
  accessExpiryEl.textContent = session.accessTokenExpiresAtUtc ?? '-';
  refreshExpiryEl.textContent = session.refreshTokenExpiresAtUtc ?? '-';
}

async function callAuth(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (res.status === 204) {
    return null;
  }

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(data?.error ?? `Request failed with status ${res.status}`);
  }

  return data;
}

document.getElementById('signup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const data = await callAuth('/auth/signup', {
      username: document.getElementById('signup-username').value,
      password: document.getElementById('signup-password').value,
      department: document.getElementById('signup-department').value
    });
    session = data;
    updateSessionUi();
    log('Sign up successful', data);
  } catch (err) {
    log('Sign up failed', { error: err.message });
  }
});

document.getElementById('signin-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const data = await callAuth('/auth/login', {
      username: document.getElementById('signin-username').value,
      password: document.getElementById('signin-password').value
    });
    session = data;
    updateSessionUi();
    log('Sign in successful', data);
  } catch (err) {
    log('Sign in failed', { error: err.message });
  }
});

document.getElementById('refresh-btn').addEventListener('click', async () => {
  if (!session.refreshToken) {
    return log('No refresh token available');
  }

  try {
    const data = await callAuth('/auth/refresh', { refreshToken: session.refreshToken });
    session = data;
    updateSessionUi();
    log('Refresh successful', data);
  } catch (err) {
    log('Refresh failed', { error: err.message });
  }
});

document.getElementById('signout-btn').addEventListener('click', async () => {
  if (!session.refreshToken) {
    session = { accessToken: null, refreshToken: null, accessTokenExpiresAtUtc: null, refreshTokenExpiresAtUtc: null };
    updateSessionUi();
    return log('Already signed out');
  }

  try {
    await callAuth('/auth/signout', { refreshToken: session.refreshToken });
    session = { accessToken: null, refreshToken: null, accessTokenExpiresAtUtc: null, refreshTokenExpiresAtUtc: null };
    updateSessionUi();
    log('Sign out successful');
  } catch (err) {
    log('Sign out failed', { error: err.message });
  }
});

document.querySelectorAll('[data-api]').forEach((button) => {
  button.addEventListener('click', async () => {
    if (!session.accessToken) {
      return log('You must sign in first.');
    }

    const method = button.dataset.method;
    const endpoint = button.dataset.api;

    const res = await fetch(endpoint, {
      method,
      headers: {
        Authorization: `Bearer ${session.accessToken}`
      }
    });

    const payload = await res.json().catch(() => ({}));
    log(`${method} ${endpoint} => ${res.status}`, payload);
  });
});

updateSessionUi();
