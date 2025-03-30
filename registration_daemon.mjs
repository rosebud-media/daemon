#!/usr/bin/env node

import dotenv from "dotenv";
dotenv.config();

import { webcrypto } from "crypto";
globalThis.crypto = webcrypto;

import { createClient } from "matrix-js-sdk";
import { Octokit } from "@octokit/rest";

// --- GitHub Configuration ---
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO;
const GITHUB_REGISTER_FILE_PATH = process.env.GITHUB_REGISTER_FILE_PATH;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH;

// --- Initialize Octokit ---
const octokit = new Octokit({ auth: GITHUB_TOKEN });

// --- Create Matrix Client ---
const client = createClient({
  baseUrl: process.env.MATRIX_HOMESERVER,
  accessToken: process.env.ACCESS_TOKEN,
  userId: process.env.USER_ID,
  deviceId: process.env.DEVICE_ID
});

// --- Define a Filter for Matrix Sync ---
const filterDefinition = {
  event_format: "client",
  room: {
    timeline: {
      limit: 10
    }
  }
};
const myFilter = { getDefinition: () => filterDefinition };

// --- Start Matrix Client Syncing ---
client.startClient({
  initialSyncLimit: 10,
  filter: myFilter
});

client.on("sync", (state) => {
  console.log("Sync state:", state);
});

// --- Helper Functions ---

// Fetch the current bloggers.json content from GitHub.
async function getBloggersJson() {
  try {
    const { data } = await octokit.repos.getContent({
      owner: GITHUB_OWNER,
      repo: GITHUB_REPO,
      path: GITHUB_REGISTER_FILE_PATH,
    });
    const content = Buffer.from(data.content, "base64").toString("utf-8");
    return { bloggers: JSON.parse(content), sha: data.sha };
  } catch (error) {
    console.error("Error fetching bloggers.json:", error);
    // If the file doesn't exist or an error occurs, start with an empty object.
    return { bloggers: {}, sha: null };
  }
}

// Update the bloggers.json file on GitHub with new content.
async function updateBloggersJson(bloggers, sha) {
  try {
    const updatedContent = Buffer.from(JSON.stringify(bloggers, null, 2)).toString("base64");
    await octokit.repos.createOrUpdateFileContents({
      owner: GITHUB_OWNER,
      repo: GITHUB_REPO,
      path: GITHUB_REGISTER_FILE_PATH,
      message: "Update blogger registration",
      content: updatedContent,
      sha: sha || undefined,
    });
    console.log("Successfully updated bloggers.json on GitHub.");
  } catch (error) {
    console.error("Error updating bloggers.json:", error);
  }
}

function canonicalize(obj) {
  if (typeof obj !== "object" || obj === null) {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(key => JSON.stringify(key) + ':' + canonicalize(obj[key])).join(',') + '}';
}

/**
 * Verifies the submission’s signature.
 * Expects submission.signature to be a base64‐encoded signature.
 * The verification is done on the JSON string of the submission data excluding the signature field.
 */
async function verifySubmissionSignature(submission) {
  if (!submission.signature) {
    console.error("No signature provided in submission.");
    return false;
  }
  
  // Separate the signature from the rest of the submission data.
  const { signature, ...submissionData } = submission;
  // Canonicalize the submission data (excluding the signature)
  const dataStr = canonicalize(submissionData);
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(dataStr);
  
  try {
    // Log the public key (JWK) being used for verification.
    console.log("Verifying submission with public key (JWK):", JSON.stringify(submission.pubkey, null, 2));
    
    // Import the public key from JWK format.
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      submission.pubkey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" }
      },
      false,
      ["verify"]
    );
    
    // Convert the base64 signature into a Uint8Array.
    const signatureBuffer = Uint8Array.from(Buffer.from(signature, "base64"));
    
    // Verify the signature.
    const isValid = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      publicKey,
      signatureBuffer,
      dataBuffer
    );

    console.log("Verifying result:", isValid);

    return isValid;
  } catch (error) {
    console.error("Error during signature verification:", error);
    return false;
  }
}


// --- Queue and Worker Implementation ---

// Our task queue to hold registration events.
const registrationQueue = [];
const MAX_WORKERS = 3;

// Worker function that continuously processes registration tasks.
async function worker() {
  while (true) {
    if (registrationQueue.length > 0) {
      const task = registrationQueue.shift();
      await processRegistrationEvent(task);
    } else {
      // If no tasks, wait briefly before checking again.
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
}

// Start the pool of workers.
for (let i = 0; i < MAX_WORKERS; i++) {
  worker();
}

// Enqueue a new registration event.
function enqueueRegistration(task) {
  registrationQueue.push(task);
  console.log(`Enqueued registration event: ${task.event.getId()}`);
}

// Process a single registration event.
async function processRegistrationEvent({ event, room }) {
  const content = event.getContent();
  const submission = content["rosebud:blogger_submission"];
  console.log("Processing blogger registration:");
  console.log(JSON.stringify(submission, null, 2));

  // Fetch the current bloggers.json from GitHub.
  const { bloggers, sha } = await getBloggersJson();
  const username = submission.username;

  // Check if the blogger already exists.
  if (!bloggers[username]) {
    // If blogger doesn't exist, create a new account.
    bloggers[username] = {
      pubkey: submission.pubkey,
      bio: submission.bio,
      profile_pic: submission.profile_pic,
      socials: submission.socials,
      wallets: submission.wallets,
      last_updated: submission.last_updated
    };
    console.log(`Creating new blogger account for ${username}.`);
  } else {
    // If blogger exists, treat this as an update.
    // Verify that the submission is signed with the blogger's private key.
    const validSignature = await verifySubmissionSignature(submission);
    if (!validSignature) {
      console.error(`Signature verification failed for blogger ${username}. Update rejected.`);
      return;
    }
    // Update the blogger's record.
    bloggers[username] = {
      pubkey: submission.pubkey,
      bio: submission.bio,
      profile_pic: submission.profile_pic,
      socials: submission.socials,
      wallets: submission.wallets,
      last_updated: submission.last_updated
    };
    console.log(`Updated blogger account for ${username}.`);
  }
  
  // Commit the updated bloggers.json file to GitHub.
  await updateBloggersJson(bloggers, sha);
  
  // Redact (delete) the processed registration event.
  try {
    const txnId = `redact-${event.getId()}-${Date.now()}`;
    await client.redactEvent(process.env.REGISTRATION_ROOM_ID, event.getId(), null, txnId);

    console.log(`Event ${event.getId()} redacted.`);
  } catch (err) {
    console.error("Failed to redact event:", err);
  }
}

// --- Matrix Event Handler ---
// Listen for events in the registration room and enqueue them for processing.
client.on("Room.timeline", async (event, room, toStartOfTimeline) => {
  // Process only events in the registration room and non-initial timeline events.
  if (room.roomId !== process.env.REGISTRATION_ROOM_ID || toStartOfTimeline) return;
  if (event.getType() !== "m.room.message") return;
  
  const content = event.getContent();
  if (!content["rosebud:blogger_submission"]) return;
  
  // Enqueue the event for processing.
  enqueueRegistration({ event, room });
});
