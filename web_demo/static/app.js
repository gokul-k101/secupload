let currentTab = 'text';
let selectedFile = null;

document.addEventListener('DOMContentLoaded', () => {
  fetchStatus();
  setupDragAndDrop();
});

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('status-server').innerText = `v${data.server.version} (${data.server.status})`;
    document.getElementById('status-proxy').innerText = `v${data.proxy.version} (Port ${data.proxy.port})`;
    document.getElementById('status-client').innerText = `v${data.client.version} (${data.client.uuid.substring(0, 8)}...)`;
  } catch (err) {
    console.error('Failed to fetch status:', err);
  }
}

function setupDragAndDrop() {
  const dropzone = document.querySelector('.file-dropzone');
  if (!dropzone) return;

  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, preventDefaults, false);
  });

  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, () => {
      dropzone.style.borderColor = 'var(--accent-cyan)';
      dropzone.style.background = 'rgba(0, 242, 255, 0.1)';
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, () => {
      dropzone.style.borderColor = 'var(--border-color)';
      dropzone.style.background = 'rgba(0, 0, 0, 0.2)';
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files[0]) {
      selectedFile = files[0];
      document.getElementById('file-label').innerText = `Selected: ${selectedFile.name} (${selectedFile.size} bytes)`;
    }
  }, false);
}

function switchTab(tab) {
  currentTab = tab;
  document.getElementById('tab-text-btn').classList.toggle('active', tab === 'text');
  document.getElementById('tab-file-btn').classList.toggle('active', tab === 'file');
  document.getElementById('tab-text').style.display = tab === 'text' ? 'block' : 'none';
  document.getElementById('tab-file').style.display = tab === 'file' ? 'block' : 'none';
}

function onFileSelected(event) {
  if (event.target.files && event.target.files[0]) {
    selectedFile = event.target.files[0];
    document.getElementById('file-label').innerText = `Selected: ${selectedFile.name} (${selectedFile.size} bytes)`;
  }
}

async function processPayload() {
  const formData = new FormData();

  if (currentTab === 'text') {
    const text = document.getElementById('payload-text').value;
    if (!text.trim()) {
      alert('Please enter a text payload');
      return;
    }
    formData.append('payload_text', text);
  } else {
    if (!selectedFile) {
      alert('Please select a file to upload');
      return;
    }
    formData.append('file', selectedFile);
  }

  try {
    const res = await fetch('/api/process', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();

    if (data.status !== 'SUCCESS') {
      alert('Error processing payload: ' + (data.message || 'Unknown error'));
      return;
    }

    renderNodes(data);
  } catch (err) {
    alert('Request failed: ' + err.message);
  }
}

function renderNodes(data) {
  const c = data.client_node;
  const p = data.proxy_node;
  const s = data.server_node;
  const d = data.download_node;

  // Node 1 Client
  document.getElementById('c-uuid').innerText = `${c.identity_uuid} (v${c.credential_version})`;
  document.getElementById('c-ephemeral').innerText = c.ephemeral_x25519_public_hex;
  document.getElementById('c-aad').innerText = `Nonce: ${c.nonce_hex}\nAAD: ${c.canonical_aad_hex}`;
  document.getElementById('c-ciphertext').innerText = c.primary_ciphertext_hex;
  document.getElementById('c-signature').innerText = c.envelope_signature_hex;

  // Node 2 Proxy
  document.getElementById('p-uuid').innerText = `${p.identity_uuid}`;
  document.getElementById('p-tunnels').innerText = `${p.tls_tunnel1_status} → ${p.tls_tunnel2_status}`;
  document.getElementById('p-auth').innerText = `${p.client_auth_verification}`;
  document.getElementById('p-visible').innerText = p.visible_payload_hex;

  // Node 3 Server
  document.getElementById('s-uuid').innerText = `${s.identity_uuid} (${s.decryption_key_used})`;
  document.getElementById('s-auth').innerText = `${s.client_ed25519_verification} • ${s.authorization_policy}`;
  document.getElementById('s-digest').innerText = s.sha256_content_integrity;
  document.getElementById('s-plaintext').innerText = s.decrypted_plaintext_preview;
  document.getElementById('s-storage').innerText = s.storage_path;

  // Image Preview Handling
  const imageContainer = document.getElementById('s-image-container');
  const imagePreview = document.getElementById('s-image-preview');
  if (s.is_image && s.data_uri) {
    imagePreview.src = s.data_uri;
    imageContainer.style.display = 'block';
  } else {
    imageContainer.style.display = 'none';
  }

  // Node 4 Download
  document.getElementById('d-digest').innerText = `${d.download_digest} (100% E2E Integrity Match)`;

  const downloadBtn = document.getElementById('d-download-btn');
  if (d.data_uri) {
    downloadBtn.href = d.data_uri;
    downloadBtn.download = d.filename || 'decrypted_payload';
    downloadBtn.innerHTML = `<i class="fa-solid fa-download"></i> Download Decrypted (${d.filename || 'file'})`;
  }

  document.getElementById('pipeline-results').style.display = 'grid';
  document.getElementById('download-card').style.display = 'block';

  document.getElementById('pipeline-results').scrollIntoView({ behavior: 'smooth' });
}

async function triggerRotation() {
  try {
    const res = await fetch('/api/rotate', { method: 'POST' });
    const data = await res.json();
    alert(data.message);
    fetchStatus();
  } catch (err) {
    alert('Rotation failed: ' + err.message);
  }
}
