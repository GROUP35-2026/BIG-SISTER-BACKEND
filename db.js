// db.js
// Tiny file-based JSON "database". Good enough for development and for you
// to literally open db.json and watch records appear/change/disappear as
// you book, edit, and delete sessions from the frontend.

const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'db.json');

function defaultData() {
  return {
    users: [],
    sessions: [] // booked counsellor sessions
  };
}

function readDb() {
  if (!fs.existsSync(DB_PATH)) {
    writeDb(defaultData());
  }
  const raw = fs.readFileSync(DB_PATH, 'utf-8');
  try {
    return JSON.parse(raw);
  } catch (err) {
    console.error('db.json was corrupted, resetting to defaults.', err);
    const fresh = defaultData();
    writeDb(fresh);
    return fresh;
  }
}

function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}

module.exports = { readDb, writeDb };
