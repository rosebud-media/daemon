// blog_post_daemon.mjs

import dotenv from "dotenv";
dotenv.config();

import crypto from "crypto";
// Polyfill global crypto if not already defined
if (!globalThis.crypto) {
  globalThis.crypto = crypto.webcrypto;
}

import { createClient } from "matrix-js-sdk";
import { promises as fs } from "fs";
import { setTimeout } from "timers/promises";
import fetch from "node-fetch";       // Make sure node-fetch is installed
import FormData from "form-data";     // Make sure form-data is installed

// --- GitHub Configuration ---
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO;
const GITHUB_FILE_PATH = process.env.GITHUB_BLOG_FILE_PATH;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH;

// --- Matrix Configuration ---
const MATRIX_HOMESERVER = process.env.MATRIX_HOMESERVER;
const USER_ID = process.env.USER_ID;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const ROOM_ID = process.env.BLOG_ROOM_ID;
const DEVICE_ID = process.env.DEVICE_ID;

// --- Pinata Configuration ---
const PINATA_API_KEY = process.env.PINATA_API_KEY;
const PINATA_API_SECRET = process.env.PINATA_API_SECRET;

// --- RSA Private Key ---
let RSA_PRIVATE_KEY;
const PRIVATE_KEY_PATH = process.env.PRIVATE_KEY_PATH; // or you could do: process.env.PRIVATE_KEY_BASE64
try {
  RSA_PRIVATE_KEY = await fs.readFile(PRIVATE_KEY_PATH, "utf8");
} catch (err) {
  console.error("Could not read private key from file:", err);
  process.exit(1);
}

// Global reference to the Matrix client
let globalMatrixClient = null;

// --- Utility: Verify RSA Signature using a JWK public key ---
function verifySignature(publicKeyJwk, data, signatureB64) {
  try {
    const publicKey = crypto.createPublicKey({
      key: publicKeyJwk,
      format: "jwk"
    });
    const signature = Buffer.from(signatureB64, "base64");
    const verified = crypto.verify(
      "sha256",
      data,
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      },
      signature
    );
    return verified;
  } catch (err) {
    console.error("Signature verification error:", err);
    return false;
  }
}

// --- Utility: Update articles.json in GitHub ---
async function updateArticles(newArticle) {
  const getUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${GITHUB_FILE_PATH}?ref=${GITHUB_BRANCH}`;
  const headers = {
    "Authorization": `token ${GITHUB_TOKEN}`,
    "Accept": "application/vnd.github.v3+json"
  };
  let currentData = [];
  let sha = null;

  try {
    const response = await fetch(getUrl, { headers });
    if (response.ok) {
      const fileData = await response.json();
      sha = fileData.sha;
      const content = Buffer.from(fileData.content, "base64").toString("utf8");
      currentData = JSON.parse(content);
    } else if (response.status === 404) {
      console.warn("articles.json does not exist in the repository. It will be created.");
    } else {
      const errorText = await response.text();
      console.error("Error fetching articles.json from GitHub:", errorText);
      return;
    }
  } catch (err) {
    console.error("Error reading articles file from GitHub:", err);
    return;
  }

  // Prepend new article at the top
  currentData.unshift(newArticle);
  const updatedContent = Buffer.from(JSON.stringify(currentData, null, 2)).toString("base64");

  const commitPayload = {
    message: `Update articles.json: Added article "${newArticle.title || "Untitled"}"`,
    content: updatedContent,
    branch: GITHUB_BRANCH
  };
  if (sha) {
    commitPayload.sha = sha;
  }

  const putUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${GITHUB_FILE_PATH}`;
  try {
    const putResponse = await fetch(putUrl, {
      method: "PUT",
      headers: {
        "Authorization": `token ${GITHUB_TOKEN}`,
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(commitPayload)
    });
    if (!putResponse.ok) {
      const errorText = await putResponse.text();
      console.error("Error updating articles.json on GitHub:", errorText);
    } else {
      console.info(`Updated articles.json on GitHub with new article: ${newArticle.title || "Untitled"}`);
    }
  } catch (err) {
    console.error("Error committing update to GitHub:", err);
  }
}

// --- Download, decrypt, and upload to Pinata (Hybrid RSA+AES + OAEP with SHA-256) ---
async function downloadAndProcessFile(fileMxcUrl, encryptionInfo, originalFilename) {
  try {
    if (!fileMxcUrl.startsWith("mxc://")) {
      console.error("Not a valid mxc:// URL, skipping download");
      return null;
    }
    console.info("START DOWNLOAD PROCESS (Hybrid RSA+AES)...");

    // If v3 returns 404, we can use the older v1 route on matrix.org
    const serverlessUrlPart = fileMxcUrl.replace("mxc://matrix.org/", "");
    const fileDownloadUrl = `https://matrix.org/_matrix/client/v1/media/download/matrix.org/${serverlessUrlPart}?access_token=${ACCESS_TOKEN}`;

    console.info(`FILE URL (hybrid approach): ${fileDownloadUrl}`);
    const response = await fetch(fileDownloadUrl);
    if (!response.ok) {
      console.error(`Failed to download file from ${fileDownloadUrl}, status: ${response.status}`);
      return null;
    }

    // This data is AES ciphertext
    const aesCiphertext = await response.arrayBuffer();

    // Check encryption info
    if (!encryptionInfo || !encryptionInfo.encryptedKey || !encryptionInfo.iv) {
      console.error("Missing encryption info (encrypted AES key or IV). Can't decrypt file.");
      return null;
    }
    const encryptedAesKeyB64 = encryptionInfo.encryptedKey;
    const ivB64 = encryptionInfo.iv;

    // Convert base64 to Buffers
    const encryptedAesKeyBuf = Buffer.from(encryptedAesKeyB64, "base64");
    const ivBuf = Buffer.from(ivB64, "base64");

    // 1) RSA-decrypt the ephemeral AES key
    let rawAesKey;
    try {
      rawAesKey = crypto.privateDecrypt(
        {
          key: RSA_PRIVATE_KEY,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256" // match WebCrypto RSA-OAEP (SHA-256)
        },
        encryptedAesKeyBuf
      );
    } catch (err) {
      console.error("RSA decryption of AES key failed:", err);
      return null;
    }
    console.info("Successfully RSA-decrypted the ephemeral AES key.");

    // 2) AES-GCM decrypt
    let aesKey;
    try {
      aesKey = await crypto.webcrypto.subtle.importKey(
        "raw",
        rawAesKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );
    } catch (err) {
      console.error("Failed to import the ephemeral AES key:", err);
      return null;
    }

    let decryptedFile;
    try {
      decryptedFile = await crypto.webcrypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBuf },
        aesKey,
        aesCiphertext
      );
    } catch (err) {
      console.error("AES-GCM decryption failed:", err);
      return null;
    }

    console.info("Successfully AES-decrypted the file. Ready to upload to Pinata.");

    // Use original filename if present
    const pinataFilename = originalFilename || "blog_attachment.bin";

    // 3) Upload decrypted file to Pinata
    const formData = new FormData();
    formData.append("file", Buffer.from(decryptedFile), { filename: pinataFilename });

    const pinataOptions = JSON.stringify({ cidVersion: 0 });
    const pinataMetadata = JSON.stringify({ name: pinataFilename });
    formData.append("pinataOptions", pinataOptions);
    formData.append("pinataMetadata", pinataMetadata);

    const pinataEndpoint = "https://api.pinata.cloud/pinning/pinFileToIPFS";
    const pinataResp = await fetch(pinataEndpoint, {
      method: "POST",
      headers: {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_API_SECRET
      },
      body: formData
    });

    if (!pinataResp.ok) {
      const pinataError = await pinataResp.text();
      console.error("Pinata upload error:", pinataError);
      return null;
    }

    const pinataJson = await pinataResp.json();
    const ipfsHash = pinataJson.IpfsHash;
    console.info("File uploaded to Pinata. CID:", ipfsHash);

    return ipfsHash;
  } catch (err) {
    console.error("Error in downloadAndProcessFile (hybrid decryption):", err);
    return null;
  }
}

// --- Process a single blog post event ---
async function processEvent(event) {
  try {
    const content = event.getContent();
    const metadata = content["rosebud:metadata"];
    if (!metadata) {
      console.info("Event does not contain blog metadata. Skipping.");
      return;
    }

    const username = metadata.author || "Anonymous";
    // Verify signature if not anonymous
    if (username !== "Anonymous") {
      const signature = metadata.signature;
      const signingPublicKey = metadata.signingPublicKey;
      if (!signature || !signingPublicKey) {
        console.error(`Missing signature or public key for user ${username}. Skipping event.`);
        return;
      }
      const fileHashB64 = metadata.fileHash;
      if (!fileHashB64) {
        console.error(`Missing file hash for signature verification for user ${username}. Skipping event.`);
        return;
      }
      const fileHashBuffer = Buffer.from(fileHashB64, "base64");
      if (!verifySignature(signingPublicKey, fileHashBuffer, signature)) {
        console.error(`Signature verification failed for user ${username}. Skipping event.`);
        return;
      }
      console.info(`Signature verified for user ${username}.`);
    } else {
      console.info("Anonymous submission; skipping signature verification.");
    }

    // If there's a file to be processed, do it
    let ipfsCid = null;
    if (metadata.fileMxc) {
      // Retrieve rosebud:encryption from the content
      const encryptionObj = content["rosebud:encryption"];
      // Pass encryptionObj and the original filename
      ipfsCid = await downloadAndProcessFile(
        metadata.fileMxc,
        encryptionObj,
        metadata.originalFilename
      );
    }

    // Build the article record
    const article = {
      title: metadata.title,
      author: username,
      summary: metadata.summary,
      dateApproved: metadata.dateApproved,
      tags: metadata.tags,
      mature: metadata.mature,
      timestamp: metadata.timestamp,
      originalFilename: metadata.originalFilename,
      cid: ipfsCid
    };

    // Update articles.json in GitHub
    await updateArticles(article);

    // Optionally, redact the event from Matrix
    if (globalMatrixClient && event.getId()) {
      const txnId = `redact-${event.getId()}-${Date.now()}`;
      console.info(`Attempting to redact event ${event.getId()} with txnId ${txnId}...`);
      try {
        await globalMatrixClient.redactEvent(ROOM_ID, event.getId(), null, txnId);
        console.info(`Redacted event ${event.getId()} from room ${ROOM_ID}.`);
      } catch (redactErr) {
        console.error(`Failed to redact event ${event.getId()}:`, redactErr);
      }
    }
  } catch (err) {
    console.error("Error processing event:", err);
  }
}

// --- Queue and Worker Implementation ---
class EventQueue {
  constructor(concurrency = 3) {
    this.queue = [];
    this.concurrency = concurrency;
    this.activeWorkers = 0;
  }

  enqueue(event) {
    this.queue.push(event);
    this.processQueue();
  }

  async processQueue() {
    while (this.queue.length > 0 && this.activeWorkers < this.concurrency) {
      const event = this.queue.shift();
      this.activeWorkers++;
      processEvent(event)
        .catch((err) => console.error("Worker error:", err))
        .finally(() => {
          this.activeWorkers--;
          this.processQueue();
        });
    }
  }
}

// --- Main Daemon Function ---
async function main() {
  const client = createClient({
    baseUrl: MATRIX_HOMESERVER,
    accessToken: ACCESS_TOKEN,
    userId: USER_ID,
    deviceId: DEVICE_ID
  });

  globalMatrixClient = client;
  const eventQueue = new EventQueue(3);

  client.on("Room.timeline", (event, room, toStartOfTimeline) => {
    if (toStartOfTimeline || room.roomId !== ROOM_ID) return;
    eventQueue.enqueue(event);
  });

  console.info("Daemon started. Listening for new blog post events...");
  await client.startClient({ initialSyncLimit: 10 });
}

main().catch((err) => {
  console.error("Daemon encountered an error:", err);
  process.exit(1);
});
