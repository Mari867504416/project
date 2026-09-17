/* =========================================================
   ONE-OFF MIGRATION: backfill metadata.* on existing chunks

   IMPORTANT — this is corrected to match the REAL schema used
   by server.js:
     - model name  : DriveChunk   (your pasted script used "Chunk")
     - file field  : fileName     (same)
     - id field    : driveFileId  (your pasted script used "fileId")
     - collection  : left to mongoose's default for "DriveChunk"
                     (drivechunks) — same as server.js, so it will
                     NOT create/use a separate "chunks" collection.

   Run this ONCE, after deploying the updated server.js (so the
   `metadata` field exists on the schema), to fill in metadata
   for chunks that were inserted before this change. New chunks
   created after the update already get metadata automatically
   via extractMetadata() in server.js.

   Usage:
     MONGODB_URI="<your connection string>" node migrate-metadata.js
========================================================= */

const mongoose = require('mongoose');

const MONGODB_URI = process.env.MONGODB_URI;

const driveChunkSchema = new mongoose.Schema(
  {
    driveFileId: { type: String, required: true, index: true },
    fileName: { type: String, required: true },
    driveUrl: { type: String, default: '' },
    chunkIndex: { type: Number, required: true },
    text: { type: String, required: true },
    embedding: { type: [Number], required: true },

    metadata: {
      department: { type: String, default: null },
      category: { type: String, default: null },
      goNumber: { type: String, default: null },
      goDate: { type: String, default: null },
      year: { type: Number, default: null }
    }
  },
  {
    strict: false,
    timestamps: true
  }
);

const DriveChunk = mongoose.model('DriveChunk', driveChunkSchema);


// ------------------------------------
// Metadata extraction — identical logic to extractMetadata()
// in server.js, kept in sync so migrated data matches what
// newly-synced files will get.
// ------------------------------------

function extractMetadata(fileName) {

  const metadata = {
    department: null,
    category: null,
    goNumber: null,
    goDate: null,
    year: null
  };

  const name = fileName || '';

  let match = name.match(
    /G\.?\s*O\.?\s*(?:\(?Ms\)?\.?)?\s*(?:No\.?)?\s*(\d+)/i
  );

  if (match) {
    metadata.goNumber = match[1];
  }

  match = name.match(
    /\b(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{4})\b/
  );

  if (match) {

    const day = match[1].padStart(2, '0');
    const month = match[2].padStart(2, '0');
    const year = match[3];

    metadata.goDate = `${day}.${month}.${year}`;
    metadata.year = Number(year);
  }

  if (!metadata.year) {

    match = name.match(/\b(19|20)\d{2}\b/);

    if (match) {
      metadata.year = Number(match[0]);
    }
  }

  const departments = [
    'Revenue', 'Home', 'Finance', 'Transport', 'Education',
    'Health', 'Social Welfare', 'Rural Development',
    'Municipal Administration', 'Industries', 'Labour',
    'Agriculture'
  ];

  for (const dept of departments) {
    if (name.toLowerCase().includes(dept.toLowerCase())) {
      metadata.department = dept;
      break;
    }
  }

  if (/OAP|Old Age Pension/i.test(name)) {
    metadata.category = 'OAP';
  } else if (/Pension/i.test(name)) {
    metadata.category = 'Pension';
  } else if (/Land|Patta|Assignment/i.test(name)) {
    metadata.category = 'Land';
  } else if (/Explosive|Explosives/i.test(name)) {
    metadata.category = 'Explosives';
  } else if (/Petroleum/i.test(name)) {
    metadata.category = 'Petroleum';
  } else if (/Establishment|Estt/i.test(name)) {
    metadata.category = 'Establishment';
  } else if (/Pensioner|Retirement/i.test(name)) {
    metadata.category = 'Pension';
  }

  return metadata;
}


// ------------------------------------
// Migration
// ------------------------------------

async function migrate() {

  try {

    console.log('Connecting MongoDB...');
    await mongoose.connect(MONGODB_URI);
    console.log('MongoDB connected.');
    console.log(`Target collection: ${DriveChunk.collection.name}`);

    const cursor = DriveChunk.find({
      fileName: { $exists: true, $ne: '' }
    }).cursor();

    let total = 0;
    let updated = 0;

    for await (const chunk of cursor) {

      total++;

      const metadata = extractMetadata(chunk.fileName);

      await DriveChunk.updateOne(
        { _id: chunk._id },
        { $set: { metadata } }
      );

      updated++;

      console.log(`Updated ${updated}: ${chunk.fileName}`, metadata);
    }

    console.log('--------------------------------');
    console.log(`Total chunks : ${total}`);
    console.log(`Updated      : ${updated}`);
    console.log('--------------------------------');

    await mongoose.disconnect();

  } catch (error) {

    console.error('Migration error:', error);
    process.exit(1);
  }
}

migrate();
