const button = document.querySelector("#passkey");
const feedback = document.querySelector("#passkey-status");
const invite = button?.dataset.mode === "invite" ? location.hash.slice(1) : "";

if (invite) {
  history.replaceState(null, "", location.pathname);
} else if (button?.dataset.mode === "invite") {
  button.disabled = true;
  feedback.textContent = "Reopen the original enrollment link to continue.";
}

function fromBase64url(value) {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

function toBase64url(buffer) {
  return btoa(Array.from(new Uint8Array(buffer), value => String.fromCharCode(value)).join(""))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function browserOptions(options, create) {
  const method = create ? "parseCreationOptionsFromJSON" : "parseRequestOptionsFromJSON";
  if (typeof PublicKeyCredential[method] === "function") {
    return PublicKeyCredential[method](options);
  }
  options.challenge = fromBase64url(options.challenge);
  if (create) options.user.id = fromBase64url(options.user.id);
  for (const key of (create ? options.excludeCredentials : options.allowCredentials) || []) {
    key.id = fromBase64url(key.id);
  }
  return options;
}

function serialize(credential, create) {
  if (typeof credential.toJSON === "function") return credential.toJSON();
  const result = credential.response;
  const response = { clientDataJSON: toBase64url(result.clientDataJSON) };
  if (create) {
    response.attestationObject = toBase64url(result.attestationObject);
    response.transports = result.getTransports?.() || [];
  } else {
    response.authenticatorData = toBase64url(result.authenticatorData);
    response.signature = toBase64url(result.signature);
    response.userHandle = result.userHandle ? toBase64url(result.userHandle) : null;
  }
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "The passkey request failed.");
  return result;
}

button?.addEventListener("click", async () => {
  if (!window.PublicKeyCredential) {
    feedback.textContent = "This browser cannot use passkeys here. Open the portal over HTTPS.";
    return;
  }
  button.disabled = true;
  feedback.textContent = "Waiting for your passkey…";
  const mode = button.dataset.mode;
  const create = mode !== "login";
  try {
    const { options } = await post(`/passkeys/${mode}/begin`, { invite, target: button.dataset.target });
    const publicKey = browserOptions(options, create);
    const credential = await (create
      ? navigator.credentials.create({ publicKey })
      : navigator.credentials.get({ publicKey }));
    const { next } = await post(`/passkeys/${mode}/finish`, { credential: serialize(credential, create) });
    location.assign(next);
  } catch (error) {
    feedback.textContent = error.name === "NotAllowedError"
      ? "Passkey prompt closed. Try again when you’re ready."
      : error.message;
    button.disabled = false;
  }
});
