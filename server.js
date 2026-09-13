require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const { GoogleGenAI } = require('@google/genai');
const { google } = require('googleapis');

const fs = require('fs');
const path = require('path');
const os = require('os');
const pdfParse = require('pdf-parse');

const app = express();
const activeAiSearches = new Map();

const AI_SEARCH_DUPLICATE_WINDOW = 5000;

app.set('trust proxy', 1);


/* =========================================================
   GEMINI AI
========================================================= */

console.log(
  'GEMINI_API_KEY loaded:',
  !!process.env.GEMINI_API_KEY
);

const gemini = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});


/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(helmet());

app.use(cors());

app.use(
  express.json({
    limit: '2mb'
  })
);


/* =========================================================
   GENERAL RATE LIMITER
========================================================= */

const limiter = rateLimit({

  windowMs:
    15 * 60 * 1000,

  max:
    100,

  message: {
    error:
      'Too many requests. Please try again later.'
  }

});

app.use(limiter);


/* =========================================================
   LOGIN RATE LIMITER
========================================================= */

const loginLimiter = rateLimit({

  windowMs:
    15 * 60 * 1000,

  max:
    20,

  message: {
    error:
      'Too many login attempts. Please try again after 15 minutes.'
  }

});


/* =========================================================
   ASYNC ERROR HANDLER
========================================================= */

const asyncHandler =
  fn =>
    (req, res, next) =>
      Promise
        .resolve(
          fn(req, res, next)
        )
        .catch(next);


/* =========================================================
   VALIDATION HELPERS
========================================================= */

function isValidMobile(m) {

  return /^\d{10}$/.test(m);

}


function isValidUsername(u) {

  return /^[a-zA-Z0-9_]{4,20}$/.test(u);

}


function isValidTxnId(t) {

  return /^\d{12}$/.test(t);

}


/* =========================================================
   DATABASE CONNECTION
========================================================= */

mongoose.connect(
  process.env.MONGODB_URI
)
.then(() => {

  console.log(
    '✅ Connected to MongoDB'
  );

})
.catch(err => {

  console.error(
    '❌ MongoDB connection error:',
    err
  );

});


/* =========================================================
   GEMINI VECTOR CHUNK MODEL
========================================================= */

const driveChunkSchema =
  new mongoose.Schema(
    {
      driveFileId: {
        type: String,
        required: true,
        index: true
      },

      fileName: {
        type: String,
        required: true
      },

      driveUrl: {
        type: String,
        default: ''
      },

      chunkIndex: {
        type: Number,
        required: true
      },

      text: {
        type: String,
        required: true
      },

      embedding: {
        type: [Number],
        required: true,
        validate: {
          validator: function (v) {
            return Array.isArray(v) && v.length === 768;
          },
          message:
            'Embedding must contain exactly 768 numbers.'
        }
      }
    },
    {
      timestamps: true
    }
  );

const DriveChunk =
  mongoose.models.DriveChunk ||
  mongoose.model(
    'DriveChunk',
    driveChunkSchema
  );

/* =========================================================
   DRIVE SYNC STATUS
========================================================= */

const driveSyncFileSchema = new mongoose.Schema(
  {
    driveFileId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },

    fileName: {
      type: String,
      required: true
    },

    modifiedTime: {
      type: String,
      default: ''
    },

    md5Checksum: {
      type: String,
      default: ''
    },

    status: {
      type: String,
      enum: [
        'pending',
        'processing',
        'completed',
        'failed'
      ],
      default: 'pending',
      index: true
    },

    error: {
      type: String,
      default: ''
    },

    attempts: {
      type: Number,
      default: 0
    },

    lastAttemptAt: {
      type: Date,
      default: null
    },

    completedAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

const DriveSyncFile =
  mongoose.models.DriveSyncFile ||
  mongoose.model(
    'DriveSyncFile',
    driveSyncFileSchema
  );

/* =========================================================
   MODELS
========================================================= */


/* ---------------- ADMIN ---------------- */

const adminSchema =
  new mongoose.Schema({

    username: {

      type: String,

      required: true,

      unique: true

    },

    password: {

      type: String,

      required: true

    }

  });


const Admin =
  mongoose.models.Admin ||
  mongoose.model(
    'Admin',
    adminSchema
  );


/* ---------------- OFFICER ---------------- */

const officerSchema =
  new mongoose.Schema({

    name: {

      type: String,

      required: true,

      trim: true

    },

    address: {

      type: String,

      required: true,

      trim: true

    },

    mobile: {

      type: String,

      required: true,

      unique: true,

      validate: {

        validator:
          v =>
            /^\d{10}$/.test(v),

        message:
          props =>
            `${props.value} is not a valid 10-digit mobile number`

      }

    },

    username: {

      type: String,

      required: true,

      unique: true,

      trim: true

    },

    password: {

      type: String,

      required: true

    },

    subscribed: {

      type: Boolean,

      default: false

    },

    transactionId: {

      type: String,

      unique: true,

      sparse: true,

      validate: {

        validator:
          v =>
            !v ||
            /^\d{12}$/.test(v),

        message:
          'Transaction ID must be exactly 12 digits'

      }

    },

    subscriptionDate:
      Date,

    createdAt: {

      type: Date,

      default: Date.now

    }

  });


const Officer =
  mongoose.models.Officer ||
  mongoose.model(
    'Officer',
    officerSchema
  );


/* ---------------- RESULT ---------------- */

const resultSchema =
  new mongoose.Schema({

    username:
      String,

    name:
      String,

    address:
      String,

    score:
      Number,

    total:
      Number,

    date: {

      type: Date,

      default: Date.now

    }

  });


const Result =
  mongoose.models.Result ||
  mongoose.model(
    'Result',
    resultSchema
  );


/* ---------------- TRANSFER APPLICATION ---------------- */

const transferSchema =
  new mongoose.Schema({

    username: {

      type: String,

      required: true

    },

    transferType: {

      type: String,

      enum: [
        'One Way',
        'Mutual'
      ],

      required: true

    },

    applicantName: {

      type: String,

      required: true

    },

    workingDistrict: {

      type: String,

      required: true

    },

    designation: {

      type: String,

      enum: [

        'SRI',

        'JRI',

        'TYPIST',

        'STENO TYPIST',

        'DEPUTY TAHSILDAR',

        'TAHSILDAR'

      ],

      required: true

    },

    dateOfJoining: {

      type: Date,

      required: true

    },

    option1: {

      type: String,

      required: true

    },

    option2:
      String,

    option3:
      String,

    contactNumber: {

      type: String,

      required: true

    },

    createdAt: {

      type: Date,

      default: Date.now

    }

  });


const TransferApplication =
  mongoose.models.TransferApplication ||
  mongoose.model(
    'TransferApplication',
    transferSchema
  );


/* =========================================================
   GOOGLE DRIVE SYNC MODEL
========================================================= */

const driveSyncSchema =
  new mongoose.Schema({

    driveFileId: {

      type: String,

      required: true,

      unique: true

    },

    fileName: {

      type: String,

      required: true

    },

    modifiedTime:
      String,

    md5Checksum:
      String,

    status: {

      type: String,

      enum: [

        'indexed',

        'updated',

        'failed'

      ],

      default:
        'indexed'

    },

    chunkCount: {

      type: Number,

      default:
        0

    },

    errorMessage:
      String,

    lastSyncedAt: {

      type: Date,

      default:
        Date.now

    }

  });


const DriveSync =
  mongoose.models.DriveSync ||
  mongoose.model(
    'DriveSync',
    driveSyncSchema
  );


/* =========================================================
   CONSTANTS
========================================================= */

const ALLOWED_DESIGNATIONS = [

  'SRI',

  'JRI',

  'TYPIST',

  'STENO TYPIST',

  'DEPUTY TAHSILDAR',

  'TAHSILDAR'

];


/* =========================================================
   ADMIN RESET SECRET
========================================================= */

const ADMIN_RESET_SECRET =
  process.env.ADMIN_RESET_SECRET ||
  'TNGovt@Reset2025';


/* =========================================================
   INIT ADMIN
========================================================= */

async function initializeAdmin() {

  try {

    const exists =
      await Admin.exists({

        username:
          'admin'

      });


    if (!exists) {

      const hash =
        await bcrypt.hash(
          'admin123',
          10
        );


      await Admin.create({

        username:
          'admin',

        password:
          hash

      });


      console.log(
        '✅ Default admin created'
      );

    }

  } catch (err) {

    console.error(
      'Admin init error:',
      err
    );

  }

}

initializeAdmin();


/* =========================================================
   GOOGLE DRIVE CLIENT
========================================================= */

function getGoogleDriveClient() {

  if (
    !process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL
  ) {

    throw new Error(
      'GOOGLE_SERVICE_ACCOUNT_EMAIL is not configured.'
    );

  }


  if (
    !process.env.GOOGLE_PRIVATE_KEY
  ) {

    throw new Error(
      'GOOGLE_PRIVATE_KEY is not configured.'
    );

  }


  const auth =
    new google.auth.JWT({

      email:
        process.env
          .GOOGLE_SERVICE_ACCOUNT_EMAIL,

      key:
        process.env
          .GOOGLE_PRIVATE_KEY
          .replace(/\\n/g, '\n'),

      scopes: [

        'https://www.googleapis.com/auth/drive.readonly'

      ]

    });


  return google.drive({

    version:
      'v3',

    auth

  });

}


/* =========================================================
   GET DRIVE CHILDREN
========================================================= */

async function getDriveChildren(
  drive,
  folderId
) {

  const files = [];

  let pageToken = null;


  do {

    const response =
      await drive.files.list({

        q:
          `'${folderId}' in parents and trashed = false`,

        fields:
          'nextPageToken,files(id,name,mimeType,size,modifiedTime,md5Checksum)',

        pageSize:
          100,

        pageToken,

        supportsAllDrives:
          true,

        includeItemsFromAllDrives:
          true

      });


    files.push(
      ...(response.data.files || [])
    );


    pageToken =
      response.data.nextPageToken;


  } while (pageToken);


  return files;

}


/* =========================================================
   RECURSIVE GOOGLE DRIVE PDF SEARCH
========================================================= */

async function getDrivePdfFiles() {

  const drive =
    getGoogleDriveClient();


  const rootFolderId =
    process.env.GOOGLE_DRIVE_FOLDER_ID;


  if (!rootFolderId) {

    throw new Error(
      'GOOGLE_DRIVE_FOLDER_ID is not configured.'
    );

  }


  const pdfFiles = [];

  const foldersToProcess =
    [rootFolderId];

  const visitedFolders =
    new Set();


  while (
    foldersToProcess.length > 0
  ) {

    const currentFolderId =
      foldersToProcess.shift();


    if (
      visitedFolders.has(
        currentFolderId
      )
    ) {

      continue;

    }


    visitedFolders.add(
      currentFolderId
    );


    const children =
      await getDriveChildren(

        drive,

        currentFolderId

      );


    for (
      const file of children
    ) {

      if (
        file.mimeType ===
        'application/pdf'
      ) {

        pdfFiles.push(file);

      }

      else if (
        file.mimeType ===
        'application/vnd.google-apps.folder'
      ) {

        foldersToProcess.push(
          file.id
        );

      }

    }

  }


  return pdfFiles;

}


/* =========================================================
   DOWNLOAD GOOGLE DRIVE PDF
========================================================= */

async function downloadDriveFile(
  fileId,
  fileName
) {

  const drive =
    getGoogleDriveClient();


  const safeName =
    fileName.replace(
      /[^a-zA-Z0-9._-]/g,
      '_'
    );


  const tempPath =
    path.join(

      os.tmpdir(),

      `${Date.now()}-${safeName}`

    );


  const response =
    await drive.files.get(

      {

        fileId,

        alt:
          'media',

        acknowledgeAbuse:
          true

      },

      {

        responseType:
          'stream'

      }

    );


  return new Promise(
    (resolve, reject) => {

      const dest =
        fs.createWriteStream(
          tempPath
        );


      response.data

        .on(
          'error',
          reject
        )

        .pipe(dest);


      dest.on(
        'finish',
        () => {

          resolve(
            tempPath
          );

        }
      );


      dest.on(
        'error',
        reject
      );

    }
  );

}


/* =========================================================
   SPLIT PDF TEXT INTO CHUNKS
========================================================= */

function splitTextIntoChunks(
  text,
  chunkSize = 5000,
  overlap = 500
) {

  const cleanText =
    text

      .replace(
        /\s+/g,
        ' '
      )

      .trim();


  if (!cleanText) {

    return [];

  }


  const chunks = [];

  let start = 0;


  while (
    start < cleanText.length
  ) {

    const end =
      Math.min(

        start + chunkSize,

        cleanText.length

      );


    const chunk =
      cleanText.slice(
        start,
        end
      );


    chunks.push(
      chunk
    );


    if (
      end >= cleanText.length
    ) {

      break;

    }


    start =
      end - overlap;

  }


  return chunks;

}


/* =========================================================
   GEMINI DOCUMENT EMBEDDING
========================================================= */

async function createDocumentEmbedding(text) {

  if (!text || !text.trim()) {

    throw new Error(
      'Cannot create embedding from empty text.'
    );

  }

  const response =
    await gemini.models.embedContent({

      model:
        'gemini-embedding-001',

      contents:
        text,

      config: {

        taskType:
          'RETRIEVAL_DOCUMENT',

        outputDimensionality:
          768

      }

    });


  const values =
    response?.embeddings?.[0]?.values;


  console.log(
    '🧠 Gemini document embedding dimension:',
    values?.length || 0
  );


  if (
    !Array.isArray(values) ||
    values.length !== 768
  ) {

    throw new Error(
      `Invalid Gemini document embedding. Expected 768 dimensions, got ${values?.length || 0}`
    );

  }


  return values;

}
/* =========================================================
   GEMINI QUERY EMBEDDING
========================================================= */

/* =========================================================
   GEMINI QUERY EMBEDDING
========================================================= */

async function createQueryEmbedding(question) {

  if (!question || !question.trim()) {

    throw new Error(
      'Cannot create query embedding from empty question.'
    );

  }

  const response =
    await gemini.models.embedContent({

      model:
        'gemini-embedding-001',

      contents:
        question,

      config: {

        taskType:
          'RETRIEVAL_QUERY',

        outputDimensionality:
          768

      }

    });


  const values =
    response?.embeddings?.[0]?.values;


  console.log(
    '🔎 Query embedding dimension:',
    values?.length || 0
  );


  if (
    !Array.isArray(values) ||
    values.length !== 768
  ) {

    throw new Error(
      `Invalid Gemini query embedding. Expected 768 dimensions, got ${values?.length || 0}`
    );

  }


  return values;

}
/* =========================================================
   GEMINI GENERATE CONTENT WITH RETRY + FALLBACK
========================================================= */

/* =========================================================
   GEMINI GENERATE CONTENT
   3-MODEL FALLBACK
========================================================= */

async function generateGeminiAnswer(prompt) {

  const modelsToTry = [
    'gemini-3.6-flash',
    'gemini-2.5-flash',
    'gemini-3.5-flash-lite'
  ];

  let lastError = null;

  for (const modelName of modelsToTry) {

    try {

      console.log(
        `🤖 Trying Gemini model: ${modelName}`
      );

      const response =
        await gemini.models.generateContent({

          model: modelName,

          contents: prompt,

          config: {

            systemInstruction: `

You are an AI assistant for the Tamil Nadu Revenue Department.

Answer ONLY from the retrieved documents supplied in the prompt.

STRICT RULES:

1. Use retrieved document content as the factual source.
2. If the answer is present, answer it clearly.
3. Do not require exact wording to appear in the document.
4. You may summarize and explain the retrieved content.
5. Do not invent Government Orders.
6. Do not invent G.O. numbers.
7. Do not invent dates.
8. Do not invent Acts.
9. Do not invent Rules.
10. Do not invent Sections.
11. Do not invent proceedings.
12. Do not invent circular numbers.
13. Do not use outside knowledge.
14. If multiple retrieved documents are relevant, combine them carefully.
15. If information is partial, clearly state the limitation.
16. If the documents genuinely do not contain the answer, say:
   "கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை."
17. If the question is in Tamil, answer in Tamil.
18. If the question is in English, answer in English.
19. Mention the relevant document name when useful.
20. Preserve exact G.O. numbers, dates, Acts, Rules,
    Sections and Forms as found in the documents.

`

          }

        });

      console.log(
        `✅ Gemini answer generated using: ${modelName}`
      );

      return response;

    } catch (error) {

      lastError = error;

      const status =
        error?.status ||
        error?.code ||
        error?.error?.code;

      console.error(
        `⚠️ ${modelName} failed:`,
        status,
        error?.message || error
      );


      /*
       * 429 = QUOTA EXCEEDED
       * 503 = TEMPORARILY UNAVAILABLE
       */

      if (
        status === 429 ||
        status === 503
      ) {

        console.log(
          `🔄 ${modelName} unavailable. Trying next model...`
        );

        continue;

      }


      /*
       * Other errors should not silently
       * switch models.
       */

      throw error;

    }

  }


  /*
   * ALL MODELS FAILED
   */

  console.error(
    '❌ All Gemini models failed.'
  );

  throw lastError;

}

/* =========================================================
   INDEX ONE PDF
========================================================= */

/* =========================================================
   INDEX ONE PDF
========================================================= */

async function indexDrivePdf(file) {

  console.log(
    `📄 Indexing: ${file.name}`
  );


  let tempPath = null;


  try {

    /* =====================================================
       DOWNLOAD PDF
    ===================================================== */

    tempPath =
      await downloadDriveFile(
        file.id,
        file.name
      );


    /* =====================================================
       READ PDF
    ===================================================== */

    const pdfBuffer =
      fs.readFileSync(
        tempPath
      );


    /* =====================================================
       EXTRACT PDF TEXT
    ===================================================== */

    const pdfData =
      await pdfParse(
        pdfBuffer
      );


    const text =
      pdfData.text || '';


    if (!text.trim()) {

      console.log(
        `⚠️ No text found: ${file.name}`
      );


      return {

        success:
          false,

        reason:
          'No text found in PDF.'

      };

    }


    /* =====================================================
       SPLIT TEXT INTO CHUNKS
    ===================================================== */

    const chunks =
      splitTextIntoChunks(
        text,
        5000,
        500
      );


    console.log(
      `📚 ${chunks.length} chunks created`
    );


    if (!chunks.length) {

      return {

        success:
          false,

        reason:
          'No usable text chunks created.'

      };

    }


    /* =====================================================
       CREATE ALL EMBEDDINGS FIRST
       
       IMPORTANT:
       Do NOT delete old chunks yet.
    ===================================================== */

    const newChunks = [];


    for (
      let i = 0;
      i < chunks.length;
      i++
    ) {

      console.log(
        `🔢 Embedding chunk ${i + 1}/${chunks.length}`
      );


      const embedding =
        await createDocumentEmbedding(
          chunks[i]
        );


      /* =================================================
         VERIFY EMBEDDING
      ================================================= */

      if (
        !Array.isArray(embedding) ||
        embedding.length !== 768
      ) {

        throw new Error(
          `Invalid embedding for chunk ${i + 1}: expected 768, got ${embedding?.length || 0}`
        );

      }


      console.log(
        `✅ Embedding ${i + 1}: ${embedding.length} dimensions`
      );


      /* =================================================
         PREPARE CHUNK
      ================================================= */

      newChunks.push({

        driveFileId:
          file.id,

        fileName:
          file.name,

        driveUrl:
          `https://drive.google.com/file/d/${file.id}/view`,

        chunkIndex:
          i,

        text:
          chunks[i],

        embedding:
          embedding

      });

    }


    /* =====================================================
       ALL EMBEDDINGS SUCCESSFUL
       
       ONLY NOW DELETE OLD CHUNKS
    ===================================================== */

    console.log(
      `🗑️ Removing old chunks for: ${file.name}`
    );


    await DriveChunk.deleteMany({

      driveFileId:
        file.id

    });


    /* =====================================================
       INSERT NEW CHUNKS
    ===================================================== */
console.log(
  `🔍 Checking embeddings before MongoDB insert...`
);

newChunks.forEach((chunk, index) => {

  console.log(
    `📦 Chunk ${index + 1}: embedding = ${
      Array.isArray(chunk.embedding)
        ? chunk.embedding.length
        : 'NOT ARRAY'
    }`
  );

});

const invalidChunk =
  newChunks.findIndex(
    chunk =>
      !Array.isArray(chunk.embedding) ||
      chunk.embedding.length !== 768
  );

if (invalidChunk !== -1) {

  throw new Error(
    `Invalid embedding in chunk ${invalidChunk + 1}. Expected 768 dimensions.`
  );

}

console.log(
  `✅ All ${newChunks.length} embeddings contain 768 dimensions`
);
    console.log(
      `💾 Saving ${newChunks.length} chunks to MongoDB`
    );


    await DriveChunk.insertMany(
      newChunks
    );
const savedChunk =
  await DriveChunk.findOne({
    driveFileId: file.id
  }).lean();

console.log(
  `🧪 MongoDB verification: embedding = ${
    Array.isArray(savedChunk?.embedding)
      ? savedChunk.embedding.length
      : 'NOT ARRAY'
  }`
);

if (
  !savedChunk ||
  !Array.isArray(savedChunk.embedding) ||
  savedChunk.embedding.length !== 768
) {

  throw new Error(
    'Embedding was not saved correctly in MongoDB.'
  );
}

console.log(
  `✅ MongoDB confirmed: embedding has 768 dimensions`
);

    /* =====================================================
       SUCCESS
    ===================================================== */

    console.log(
      `✅ Indexed successfully: ${file.name}`
    );


    return {

      success:
        true,

      chunks:
        newChunks.length

    };


  } catch (error) {

    console.error(

      `❌ Indexing failed: ${file.name}`,

      error.message

    );


    return {

      success:
        false,

      error:
        error.message

    };


  } finally {

    /* =====================================================
       CLEANUP TEMPORARY PDF
    ===================================================== */

    if (
      tempPath &&
      fs.existsSync(tempPath)
    ) {

      try {

        fs.unlinkSync(
          tempPath
        );

      } catch (cleanupError) {

        console.error(

          '⚠️ Temporary file cleanup failed:',

          cleanupError.message

        );

      }

    }

  }

}
/* =========================================================
   BATCH DRIVE SYNC
========================================================= */

const DRIVE_BATCH_SIZE = 20;

let driveSyncRunning = false;


/* ---------------------------------------------------------
   GET SYNC COUNTS
--------------------------------------------------------- */

async function getDriveSyncCounts() {

  const total =
    await DriveSyncFile.countDocuments();

  const pending =
    await DriveSyncFile.countDocuments({
      status: 'pending'
    });

  const processing =
    await DriveSyncFile.countDocuments({
      status: 'processing'
    });

  const completed =
    await DriveSyncFile.countDocuments({
      status: 'completed'
    });

  const failed =
    await DriveSyncFile.countDocuments({
      status: 'failed'
    });

  return {
    total,
    pending,
    processing,
    completed,
    failed
  };
}


/* ---------------------------------------------------------
   REGISTER DRIVE FILES
--------------------------------------------------------- */

async function registerDriveFiles(files) {

  let registered = 0;

  for (const file of files) {

    if (!file.id || !file.name) {
      continue;
    }

    await DriveSyncFile.updateOne(
      {
        driveFileId: file.id
      },
      {
        $set: {
          fileName: file.name,
          modifiedTime:
            file.modifiedTime || '',
          md5Checksum:
            file.md5Checksum || ''
        },

        $setOnInsert: {
          status: 'pending',
          attempts: 0,
          error: '',
          completedAt: null
        }
      },
      {
        upsert: true
      }
    );

    registered++;
  }

  console.log(
    `📋 Registered/updated ${registered} Drive files`
  );

  return registered;
}


/* ---------------------------------------------------------
   RESET STALE PROCESSING FILES
--------------------------------------------------------- */

async function resetStaleProcessingFiles() {

  const staleTime =
    new Date(Date.now() - 30 * 60 * 1000);

  const result =
    await DriveSyncFile.updateMany(
      {
        status: 'processing',
        lastAttemptAt: {
          $lt: staleTime
        }
      },
      {
        $set: {
          status: 'pending',
          error:
            'Reset after stale processing state.'
        }
      }
    );

  if (result.modifiedCount > 0) {

    console.log(
      `♻️ Reset ${result.modifiedCount} stale processing files`
    );
  }
}


/* ---------------------------------------------------------
   CHECK WHETHER PDF ALREADY HAS VALID EMBEDDINGS
--------------------------------------------------------- */

async function hasValidPdfEmbeddings(
  driveFileId,
  modifiedTime,
  md5Checksum
) {

  const chunks =
    await DriveChunk.find(
      {
        driveFileId
      },
      {
        embedding: 1
      }
    ).lean();

  if (!chunks.length) {
    return false;
  }

  const allValid =
    chunks.every(
      chunk =>
        Array.isArray(chunk.embedding) &&
        chunk.embedding.length === 768
    );

  if (!allValid) {
    return false;
  }

  return true;
}


/* ---------------------------------------------------------
   PROCESS ONE FILE
--------------------------------------------------------- */

async function processOneDriveFile(
  syncFile
) {

  const {
    driveFileId,
    fileName,
    modifiedTime,
    md5Checksum
  } = syncFile;

  console.log('');
  console.log(
    `📄 Processing: ${fileName}`
  );
  console.log(
    `🆔 ${driveFileId}`
  );

  try {

    /*
     * Check existing valid embeddings.
     */

    const alreadyValid =
      await hasValidPdfEmbeddings(
        driveFileId,
        modifiedTime,
        md5Checksum
      );

    if (alreadyValid) {

      console.log(
        `⏭️ Already embedded: ${fileName}`
      );

      await DriveSyncFile.updateOne(
        {
          driveFileId
        },
        {
          $set: {
            status: 'completed',
            error: '',
            completedAt: new Date()
          }
        }
      );

      return {
        success: true,
        skipped: true
      };
    }


    /*
     * Mark processing.
     */

    await DriveSyncFile.updateOne(
      {
        driveFileId
      },
      {
        $set: {
          status: 'processing',
          lastAttemptAt: new Date(),
          error: ''
        },

        $inc: {
          attempts: 1
        }
      }
    );


    /*
     * Find Drive file metadata.
     */

    const file =
      await drive.files.get({
        fileId: driveFileId,
        fields:
          'id,name,mimeType,modifiedTime,md5Checksum,webViewLink'
      });


    if (
      !file.data ||
      file.data.mimeType !== 'application/pdf'
    ) {

      console.log(
        `⏭️ Not a PDF: ${fileName}`
      );

      await DriveSyncFile.updateOne(
        {
          driveFileId
        },
        {
          $set: {
            status: 'completed',
            error: 'Skipped: not a PDF.',
            completedAt: new Date()
          }
        }
      );

      return {
        success: true,
        skipped: true
      };
    }


    /*
     * IMPORTANT:
     * Use your existing indexDrivePdf()
     */

    await indexDrivePdf({
      id: file.data.id,
      name: file.data.name,
      modifiedTime:
        file.data.modifiedTime,
      md5Checksum:
        file.data.md5Checksum,
      webViewLink:
        file.data.webViewLink
    });


    /*
     * Verify embeddings after indexing.
     */

    const verified =
      await hasValidPdfEmbeddings(
        driveFileId,
        modifiedTime,
        md5Checksum
      );

    if (!verified) {

      throw new Error(
        'PDF processed but valid 768-dimensional embeddings were not found after indexing.'
      );
    }


    /*
     * Mark completed.
     */

    await DriveSyncFile.updateOne(
      {
        driveFileId
      },
      {
        $set: {
          status: 'completed',
          error: '',
          completedAt: new Date()
        }
      }
    );

    console.log(
      `✅ Completed: ${fileName}`
    );

    return {
      success: true,
      skipped: false
    };

  } catch (error) {

    console.error(
      `❌ Failed: ${fileName}`
    );

    console.error(
      error.message
    );


    /*
     * IMPORTANT:
     * Do NOT delete existing chunks here.
     * indexDrivePdf() should already protect them.
     */

    await DriveSyncFile.updateOne(
      {
        driveFileId
      },
      {
        $set: {
          status: 'failed',
          error:
            String(error.message || error)
              .substring(0, 2000)
        }
      }
    );

    return {
      success: false,
      skipped: false,
      error: error.message
    };
  }
}


/* ---------------------------------------------------------
   RUN ONE BATCH
--------------------------------------------------------- */

async function runDriveBatch(
  batchSize = DRIVE_BATCH_SIZE,
  retryFailed = false
) {

  if (driveSyncRunning) {

    throw new Error(
      'Drive sync is already running.'
    );
  }

  driveSyncRunning = true;

  try {

    await resetStaleProcessingFiles();


    const query = retryFailed
      ? {
          status: 'failed'
        }
      : {
          status: 'pending'
        };


    const files =
      await DriveSyncFile.find(query)
        .sort({
          createdAt: 1
        })
        .limit(batchSize)
        .lean();


    if (!files.length) {

      console.log(
        retryFailed
          ? '🎉 No failed files to retry.'
          : '🎉 No pending files. Sync complete.'
      );

      return {
        processed: 0,
        success: 0,
        failed: 0,
        skipped: 0
      };
    }


    console.log('');
    console.log(
      '=========================================='
    );

    console.log(
      retryFailed
        ? `🔁 RETRY BATCH: ${files.length} PDFs`
        : `🚀 BATCH: ${files.length} PDFs`
    );

    console.log(
      '=========================================='
    );


    let success = 0;
    let failed = 0;
    let skipped = 0;


    /*
     * Process sequentially.
     *
     * DO NOT use Promise.all()
     *
     * This prevents Gemini embedding quota
     * overload.
     */

    for (
      let i = 0;
      i < files.length;
      i++
    ) {

      const file = files[i];

      console.log('');
      console.log(
        `📦 Batch progress: ${i + 1}/${files.length}`
      );


      const result =
        await processOneDriveFile(file);


      if (result.success) {

        success++;

        if (result.skipped) {
          skipped++;
        }

      } else {

        failed++;
      }


      /*
       * Small delay between PDFs.
       * Helps reduce API pressure.
       */

      await new Promise(
        resolve =>
          setTimeout(resolve, 1500)
      );
    }


    const counts =
      await getDriveSyncCounts();


    console.log('');
    console.log(
      '=========================================='
    );

    console.log(
      '📊 BATCH COMPLETED'
    );

    console.log(
      '=========================================='
    );

    console.log(
      `Processed : ${files.length}`
    );

    console.log(
      `Success   : ${success}`
    );

    console.log(
      `Skipped   : ${skipped}`
    );

    console.log(
      `Failed    : ${failed}`
    );

    console.log(
      `Pending   : ${counts.pending}`
    );

    console.log(
      `Completed : ${counts.completed}`
    );

    console.log(
      `Failed DB : ${counts.failed}`
    );

    console.log(
      '=========================================='
    );


    return {
      processed: files.length,
      success,
      failed,
      skipped,
      counts
    };

  } finally {

    driveSyncRunning = false;
  }
}
/* =========================================================
   GOOGLE DRIVE → GEMINI → MONGODB SYNC
========================================================= */

async function syncGoogleDriveToGemini() {

  console.log(
    '🚀 Starting Google Drive → Gemini → MongoDB sync...'
  );


  const files =
    await getDrivePdfFiles();


  console.log(
    `📂 Found ${files.length} PDF file(s).`
  );
await registerDriveFiles(files);

  let indexed = 0;

  let updated = 0;

  let skipped = 0;

  let failed = 0;


  const details = [];


  for (
    const file of files
  ) {

    try {

      console.log(
        `📄 Checking: ${file.name}`
      );


      const existing =
        await DriveSync.findOne({

          driveFileId:
            file.id

        });


      /*
       * Skip unchanged file
       */

   const storedChunkCount =
  await DriveChunk.countDocuments({
    driveFileId: file.id
  });

const invalidChunk =
  await DriveChunk.findOne({
    driveFileId: file.id,
    $expr: {
      $ne: [
        {
          $size: {
            $ifNull: ['$embedding', []]
          }
        },
        768
      ]
    }
  }).select('_id');

const hasValidEmbeddings =
  storedChunkCount > 0 &&
  !invalidChunk &&
  storedChunkCount ===
    (existing?.chunkCount || storedChunkCount);


/* =====================================================
   SKIP ONLY IF FILE IS UNCHANGED
   AND VALID CHUNK DATA EXISTS
===================================================== */

if (

  existing &&

  existing.modifiedTime ===
    file.modifiedTime &&

  existing.md5Checksum ===
    file.md5Checksum &&

  existing.status !==
    'failed' &&

  hasValidEmbeddings

) {
  skipped++;


  details.push({

    file:
      file.name,

    status:
      'skipped',

    chunks:
      existing.chunkCount || 0

  });


  continue;

}

      /*
       * Index PDF
       */

      const result =
        await indexDrivePdf(
          file
        );


      if (
        !result.success
      ) {

        failed++;


        await DriveSync.findOneAndUpdate(

          {
            driveFileId:
              file.id
          },

          {

            driveFileId:
              file.id,

            fileName:
              file.name,

            modifiedTime:
              file.modifiedTime,

            md5Checksum:
              file.md5Checksum,

            status:
              'failed',

            chunkCount:
              0,

            errorMessage:
              result.error ||
              result.reason,

            lastSyncedAt:
              new Date()

          },

          {

            upsert:
              true

          }

        );


        details.push({

          file:
            file.name,

          status:
            'failed',

          error:
            result.error ||
            result.reason

        });


        continue;

      }


      /*
       * Save sync status
       */

      await DriveSync.findOneAndUpdate(

        {
          driveFileId:
            file.id
        },

        {

          driveFileId:
            file.id,

          fileName:
            file.name,

          modifiedTime:
            file.modifiedTime,

          md5Checksum:
            file.md5Checksum,

          status:
            existing
              ? 'updated'
              : 'indexed',

          chunkCount:
            result.chunks,

          errorMessage:
            null,

          lastSyncedAt:
            new Date()

        },

        {

          upsert:
            true,

          new:
            true

        }

      );


      if (existing) {

        updated++;

      } else {

        indexed++;

      }


      details.push({

        file:
          file.name,

        status:
          existing
            ? 'updated'
            : 'indexed',

        chunks:
          result.chunks

      });


    } catch (error) {

      failed++;


      console.error(

        `❌ Failed: ${file.name}`,

        error.message

      );


      details.push({

        file:
          file.name,

        status:
          'failed',

        error:
          error.message

      });

    }

  }


  console.log(
    '======================================'
  );

  console.log(
    'Google Drive → Gemini sync completed'
  );

  console.log(
    `Total   : ${files.length}`
  );

  console.log(
    `Indexed : ${indexed}`
  );

  console.log(
    `Updated : ${updated}`
  );

  console.log(
    `Skipped : ${skipped}`
  );

  console.log(
    `Failed  : ${failed}`
  );

  console.log(
    '======================================'
  );


  return {

    total:
      files.length,

    indexed,

    updated,

    skipped,

    failed,

    details

  };

}



/* =========================================================
   BATCH SYNC API
========================================================= */


/*
 * GET SYNC STATUS
 */

app.get(
  '/admin/drive-sync/status',
  async (req, res) => {

    try {

      const counts =
        await getDriveSyncCounts();

      const totalChunks =
        await DriveChunk.countDocuments();

      const validEmbeddings =
        await DriveChunk.countDocuments({
          embedding: {
            $size: 768
          }
        });

      res.json({
        success: true,

        running:
          driveSyncRunning,

        batchSize:
          DRIVE_BATCH_SIZE,

        files: counts,

        chunks: {
          total: totalChunks,
          validEmbeddings
        }
      });

    } catch (error) {

      console.error(
        'Sync status error:',
        error
      );

      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
);


/*
 * RUN NEXT BATCH
 */

app.post(
  '/admin/drive-sync/batch',
  async (req, res) => {

    try {

      const requestedSize =
        Number(req.body?.batchSize) ||
        DRIVE_BATCH_SIZE;

      const batchSize =
        Math.min(
          Math.max(requestedSize, 1),
          50
        );


      const result =
        await runDriveBatch(
          batchSize,
          false
        );


      res.json({
        success: true,
        mode: 'batch',
        result
      });

    } catch (error) {

      console.error(
        'Batch sync error:',
        error
      );

      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
);


/*
 * RETRY FAILED FILES
 */

app.post(
  '/admin/drive-sync/retry-failed',
  async (req, res) => {

    try {

      const requestedSize =
        Number(req.body?.batchSize) ||
        DRIVE_BATCH_SIZE;

      const batchSize =
        Math.min(
          Math.max(requestedSize, 1),
          50
        );


      const result =
        await runDriveBatch(
          batchSize,
          true
        );


      res.json({
        success: true,
        mode: 'retry-failed',
        result
      });

    } catch (error) {

      console.error(
        'Retry failed error:',
        error
      );

      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
);


/*
 * RESET FAILED FILES TO PENDING
 *
 * Useful if you want to process them later
 */

app.post(
  '/admin/drive-sync/reset-failed',
  async (req, res) => {

    try {

      const result =
        await DriveSyncFile.updateMany(
          {
            status: 'failed'
          },
          {
            $set: {
              status: 'pending',
              error: ''
            }
          }
        );


      res.json({
        success: true,
        reset:
          result.modifiedCount
      });

    } catch (error) {

      console.error(
        'Reset failed error:',
        error
      );

      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
);
/* =========================================================
   MONGODB VECTOR SEARCH
========================================================= */

/* =========================================================
   MONGODB VECTOR SEARCH
========================================================= */

/* =========================================================
   MONGODB VECTOR SEARCH
========================================================= */

/* =========================================================
   PHASE 2 - KEYWORD SEARCH
========================================================= */

async function searchKeywordChunks(question, limit = 10) {

  const cleanQuestion =
    String(question || '')
      .trim()
      .replace(/\s+/g, ' ');

  if (!cleanQuestion) {
    return [];
  }

  console.log(
    `🔤 Keyword search: ${cleanQuestion}`
  );


  /*
   * Split question into useful search terms
   */

  const terms =
    cleanQuestion
      .split(/\s+/)
      .map(term =>
        term
          .replace(/[^\p{L}\p{N}.-]/gu, '')
          .trim()
      )
      .filter(term => term.length >= 2);


  if (!terms.length) {
    return [];
  }


  /*
   * Escape regex characters
   */

  const escapedTerms =
    terms.map(term =>
      term.replace(
        /[.*+?^${}()|[\]\\]/g,
        '\\$&'
      )
    );


  /*
   * Search ALL important terms.
   *
   * $and means every term should be present.
   */

  const conditions =
    escapedTerms.map(term => ({
      $or: [
        {
          text: {
            $regex: term,
            $options: 'i'
          }
        },
        {
          fileName: {
            $regex: term,
            $options: 'i'
          }
        }
      ]
    }));


  const results =
    await DriveChunk.find({
      $and: conditions
    })
    .select({
      _id: 0,
      driveFileId: 1,
      fileName: 1,
      driveUrl: 1,
      chunkIndex: 1,
      text: 1
    })
    .limit(limit)
    .lean();


  console.log(
    `🔤 Keyword results: ${results.length}`
  );


  results.forEach(
    (item, index) => {

      console.log(
        `🔤 Keyword ${index + 1}:`,
        item.fileName,
        '| chunk:',
        item.chunkIndex
      );

    }
  );


  return results;

}

/* =========================================================
   VECTOR SEARCH
========================================================= */

async function searchRelevantChunks(
  question,
  limit = 5
) {

  console.log(
    '📊 Total DriveChunks:',
    await DriveChunk.countDocuments()
  );

  console.log(
    '📊 Valid embeddings:',
    await DriveChunk.countDocuments({
      embedding: { $size: 768 }
    })
  );


  /*
   * Create query embedding
   */

  const queryEmbedding =
    await createQueryEmbedding(
      question
    );


  console.log(
    '🔎 Query embedding dimension:',
    queryEmbedding.length
  );


  /*
   * MongoDB Atlas Vector Search
   */

  const results =
    await DriveChunk.aggregate([

      {
        $vectorSearch: {

          index:
            'revenue_vector_index',

          path:
            'embedding',

          queryVector:
            queryEmbedding,

          numCandidates:
            Math.max(
              100,
              limit * 20
            ),

          limit:
            limit

        }

      },


      {
        $project: {

          _id: 0,

          driveFileId: 1,

          fileName: 1,

          driveUrl: 1,

          chunkIndex: 1,

          text: 1,

          score: {
            $meta:
              'vectorSearchScore'
          }

        }

      }

    ]);


  console.log(
    `📚 Retrieved ${results.length} relevant chunks`
  );


  return results;

}
/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  '/',
  (req, res) => {

    res.json({

      status:
        'TN Govt Servant Portal API running ✅',

      ai:
        'Gemini RAG',

      database:
        'MongoDB'

    });

  }
);


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  '/admin/login',

  loginLimiter,

  asyncHandler(
    async (req, res) => {

      const {
        username,
        password
      } = req.body;


      if (
        !username ||
        !password
      ) {

        return res.status(400).json({

          error:
            'Username and password required.'

        });

      }


      const admin =
        await Admin.findOne({

          username

        });


      if (
        !admin ||
        !(await bcrypt.compare(

          password,

          admin.password

        ))

      ) {

        return res.status(401).json({

          error:
            'Invalid credentials.'

        });

      }


      res.json({

        message:
          'Admin login successful'

      });

    }

  )

);


/* =========================================================
   ADMIN RESET PASSWORD
========================================================= */

app.post(
  '/admin/reset-password',

  asyncHandler(
    async (req, res) => {

      const {
        secretCode,
        password
      } = req.body;


      if (
        !secretCode ||
        !password
      ) {

        return res.status(400).json({

          error:
            'Secret code and new password required.'

        });

      }


      if (
        secretCode !==
        ADMIN_RESET_SECRET
      ) {

        return res.status(403).json({

          error:
            'Invalid secret code.'

        });

      }


      if (
        password.length < 8
      ) {

        return res.status(400).json({

          error:
            'Password must be at least 8 characters.'

        });

      }


      const hash =
        await bcrypt.hash(
          password,
          10
        );


      await Admin.updateOne(

        {
          username:
            'admin'
        },

        {

          password:
            hash

        }

      );


      res.json({

        message:
          'Admin password reset successfully.'

      });

    }

  )

);


/* =========================================================
   OFFICER LOGIN
========================================================= */

app.post(
  '/login',

  loginLimiter,

  asyncHandler(
    async (req, res) => {

      const {
        username,
        password
      } = req.body;


      if (
        !username ||
        !password
      ) {

        return res.status(400).json({

          error:
            'Username and password required.'

        });

      }


      const officer =
        await Officer.findOne({

          username

        });


      if (
        !officer ||
        !(await bcrypt.compare(

          password,

          officer.password

        ))

      ) {

        return res.status(401).json({

          error:
            'Invalid credentials.'

        });

      }


      const obj =
        officer.toObject();


      delete obj.password;


      res.json({

        message:
          'Login successful',

        officer:
          obj,

        subscribed:
          officer.subscribed

      });

    }

  )

);


/* =========================================================
   OFFICER SIGNUP
========================================================= */

app.post(
  '/signup',

  asyncHandler(
    async (req, res) => {

      const {

        name,

        address,

        mobile,

        username,

        password

      } = req.body;


      if (

        !name ||

        !address ||

        !mobile ||

        !username ||

        !password

      ) {

        return res.status(400).json({

          error:
            'All fields are required.'

        });

      }


      if (
        !isValidMobile(mobile)
      ) {

        return res.status(400).json({

          error:
            'Mobile must be exactly 10 digits.'

        });

      }


      if (
        !isValidUsername(username)
      ) {

        return res.status(400).json({

          error:
            'Username: 4-20 chars, letters/numbers/underscore only.'

        });

      }


      if (
        password.length < 8
      ) {

        return res.status(400).json({

          error:
            'Password must be at least 8 characters.'

        });

      }


      const existingUser =
        await Officer.findOne({

          $or: [

            {
              username
            },

            {
              mobile
            }

          ]

        });


      if (existingUser) {

        if (
          existingUser.username ===
          username
        ) {

          return res.status(409).json({

            error:
              'Username already taken.'

          });

        }


        if (
          existingUser.mobile ===
          mobile
        ) {

          return res.status(409).json({

            error:
              'Mobile number already registered.'

          });

        }

      }


      const hash =
        await bcrypt.hash(
          password,
          10
        );


      const officer =
        await Officer.create({

          name,

          address,

          mobile,

          username,

          password:
            hash

        });


      const obj =
        officer.toObject();


      delete obj.password;


      res.json({

        message:
          'Officer registered successfully.',

        officer:
          obj

      });

    }

  )

);


/* =========================================================
   OFFICER RESET PASSWORD
========================================================= */

app.post(
  '/officer/reset-password',

  asyncHandler(
    async (req, res) => {

      const {

        username,

        mobile,

        password

      } = req.body;


      if (

        !username ||

        !mobile ||

        !password

      ) {

        return res.status(400).json({

          error:
            'All fields required.'

        });

      }


      if (
        !isValidMobile(mobile)
      ) {

        return res.status(400).json({

          error:
            'Invalid mobile number.'

        });

      }


      if (
        password.length < 8
      ) {

        return res.status(400).json({

          error:
            'Password must be at least 8 characters.'

        });

      }


      const officer =
        await Officer.findOne({

          username,

          mobile

        });


      if (!officer) {

        return res.status(404).json({

          error:
            'No officer found with this username and mobile.'

        });

      }


      officer.password =
        await bcrypt.hash(
          password,
          10
        );


      await officer.save();


      res.json({

        message:
          'Password reset successfully.'

      });

    }

  )

);


/* =========================================================
   SUBMIT TRANSACTION
========================================================= */

app.post(
  '/submit-transaction',

  asyncHandler(
    async (req, res) => {

      const {

        username,

        transactionId

      } = req.body;


      if (
        !username ||
        !transactionId
      ) {

        return res.status(400).json({

          error:
            'Username and Transaction ID required.'

        });

      }


      if (
        !isValidTxnId(
          transactionId
        )
      ) {

        return res.status(400).json({

          error:
            'Transaction ID must be exactly 12 digits.'

        });

      }


      const existing =
        await Officer.findOne({

          transactionId

        });


      if (

        existing &&

        existing.username !==
          username

      ) {

        return res.status(409).json({

          error:
            'This Transaction ID is already registered.'

        });

      }


      const officer =
        await Officer.findOneAndUpdate(

          {
            username
          },

          {

            transactionId,

            subscribed:
              false

          },

          {
            new:
              true
          }

        );


      if (!officer) {

        return res.status(404).json({

          error:
            'Officer not found.'

        });

      }


      res.json({

        message:
          'Transaction ID submitted successfully. Awaiting admin approval.'

      });

    }

  )

);


/* =========================================================
   OFFICER STATUS
========================================================= */

app.post(
  '/officer/status',

  asyncHandler(
    async (req, res) => {

      const officer =
        await Officer.findOne({

          username:
            req.body.username

        });


      if (!officer) {

        return res.status(404).json({

          error:
            'Officer not found.'

        });

      }


      res.json({

        activated:
          officer.subscribed

      });

    }

  )

);


/* =========================================================
   GET ALL OFFICERS
========================================================= */

app.get(
  '/admin/officers',

  asyncHandler(
    async (req, res) => {

      const officers =
        await Officer.find(

          {},

          {
            password:
              0
          }

        )
        .sort({

          createdAt:
            -1

        });


      res.json(
        officers
      );

    }

  )

);


/* =========================================================
   ACTIVATE SUBSCRIPTION
========================================================= */

app.post(
  '/admin/activate',

  asyncHandler(
    async (req, res) => {

      const {
        transactionId
      } = req.body;


      if (
        !isValidTxnId(
          transactionId
        )
      ) {

        return res.status(400).json({

          error:
            'Transaction ID must be 12 digits.'

        });

      }


      const officer =
        await Officer.findOne({

          transactionId

        });


      if (!officer) {

        return res.status(404).json({

          error:
            'No officer found with this Transaction ID.'

        });

      }


      if (
        officer.subscribed
      ) {

        return res.status(409).json({

          error:
            'This officer is already activated.'

        });

      }


      officer.subscribed =
        true;


      officer.subscriptionDate =
        new Date();


      await officer.save();


      res.json({

        message:
          `Subscription activated for ${officer.name} (${officer.username}).`

      });

    }

  )

);


/* =========================================================
   EDIT OFFICER
========================================================= */

app.post(
  '/admin/officer/update',

  asyncHandler(
    async (req, res) => {

      const {

        username,

        name,

        address,

        mobile

      } = req.body;


      if (!username) {

        return res.status(400).json({

          error:
            'Username required to identify officer.'

        });

      }


      if (
        !name ||
        name.trim().length === 0
      ) {

        return res.status(400).json({

          error:
            'Name cannot be empty.'

        });

      }


      if (
        !isValidMobile(mobile)
      ) {

        return res.status(400).json({

          error:
            'Mobile must be exactly 10 digits.'

        });

      }


      const conflict =
        await Officer.findOne({

          mobile,

          username: {

            $ne:
              username

          }

        });


      if (conflict) {

        return res.status(409).json({

          error:
            'This mobile number is used by another officer.'

        });

      }


      const officer =
        await Officer.findOneAndUpdate(

          {
            username
          },

          {

            name:
              name.trim(),

            address:
              (address || '').trim(),

            mobile

          },

          {

            new:
              true,

            runValidators:
              true

          }

        );


      if (!officer) {

        return res.status(404).json({

          error:
            'Officer not found.'

        });

      }


      const obj =
        officer.toObject();


      delete obj.password;


      res.json({

        message:
          'Officer details updated successfully.',

        officer:
          obj

      });

    }

  )

);


/* =========================================================
   DELETE OFFICER
========================================================= */

app.post(
  '/admin/officer/delete',

  asyncHandler(
    async (req, res) => {

      const {
        username
      } = req.body;


      if (!username) {

        return res.status(400).json({

          error:
            'Username required.'

        });

      }


      const officer =
        await Officer.findOneAndDelete({

          username

        });


      if (!officer) {

        return res.status(404).json({

          error:
            'Officer not found.'

        });

      }


      res.json({

        message:
          `Officer "${username}" deleted successfully.`

      });

    }

  )

);


/* =========================================================
   SUBMIT RESULT
========================================================= */

app.post(
  '/submit-result',

  asyncHandler(
    async (req, res) => {

      const {

        username,

        name,

        address,

        score,

        total

      } = req.body;


      if (

        !username ||

        score === undefined ||

        total === undefined

      ) {

        return res.status(400).json({

          error:
            'username, score, and total are required.'

        });

      }


      await Result.create({

        username,

        name,

        address,

        score,

        total

      });


      res.json({

        message:
          'Result submitted successfully.'

      });

    }

  )

);


/* =========================================================
   GET RESULTS
========================================================= */

app.get(
  '/get-results',

  asyncHandler(
    async (req, res) => {

      const list =
        await Result.find()
          .sort({

            date:
              -1

          });


      res.json(
        list
      );

    }

  )

);


/* =========================================================
   APPLY TRANSFER
========================================================= */

app.post(
  '/transfer/apply',

  asyncHandler(
    async (req, res) => {

      const designation =
        req.body.designation
          ?.trim()
          .toUpperCase();


      if (
        !ALLOWED_DESIGNATIONS.includes(
          designation
        )
      ) {

        return res.status(400).json({

          error:
            `Invalid designation. Allowed: ${ALLOWED_DESIGNATIONS.join(', ')}`

        });

      }


      const required = [

        'username',

        'transferType',

        'applicantName',

        'workingDistrict',

        'dateOfJoining',

        'option1',

        'contactNumber'

      ];


      for (
        const field of required
      ) {

        if (
          !req.body[field]
        ) {

          return res.status(400).json({

            error:
              `${field} is required.`

          });

        }

      }


      const application =
        await TransferApplication.create({

          ...req.body,

          designation

        });


      res.json({

        message:
          'Transfer application submitted successfully.',

        id:
          application._id

      });

    }

  )

);


/* =========================================================
   TRANSFER LIST HELPER
========================================================= */

const transferList =
  designation =>
    asyncHandler(
      async (req, res) => {

        const filter =
          designation
            ? {
                designation
              }
            : {};


        const apps =
          await TransferApplication
            .find(filter)
            .sort({

              createdAt:
                -1

            });


        res.json(
          apps
        );

      }
    );


app.get(
  '/transfer/all',
  transferList(null)
);

app.get(
  '/transfer/sri',
  transferList('SRI')
);

app.get(
  '/transfer/jri',
  transferList('JRI')
);

app.get(
  '/transfer/typist',
  transferList('TYPIST')
);

app.get(
  '/transfer/stenotypist',
  transferList('STENO TYPIST')
);

app.get(
  '/transfer/deputytahsildar',
  transferList('DEPUTY TAHSILDAR')
);

app.get(
  '/transfer/tahsildar',
  transferList('TAHSILDAR')
);


/* =========================================================
   ADMIN - GOOGLE DRIVE → GEMINI SYNC
========================================================= */

app.post(
  '/admin/sync-drive',

  asyncHandler(
    async (req, res) => {

      const suppliedSecret =
        req.headers[
          'x-sync-secret'
        ];


      if (
        !process.env.DRIVE_SYNC_SECRET
      ) {

        return res.status(500).json({

          error:
            'DRIVE_SYNC_SECRET is not configured.'

        });

      }


      if (

        !suppliedSecret ||

        suppliedSecret !==
          process.env.DRIVE_SYNC_SECRET

      ) {

        return res.status(403).json({

          error:
            'Unauthorized.'

        });

      }


      const result =
        await syncGoogleDriveToGemini();


      res.json({

        success:
          true,

        message:
          'Google Drive → Gemini → MongoDB sync completed.',

        result

      });

    }

  )

);


/* =========================================================
   ADMIN - SYNC STATUS
========================================================= */

app.get(
  '/admin/sync-status',

  asyncHandler(
    async (req, res) => {

      const suppliedSecret =
        req.headers[
          'x-sync-secret'
        ];


      if (

        !process.env.DRIVE_SYNC_SECRET ||

        suppliedSecret !==
          process.env.DRIVE_SYNC_SECRET

      ) {

        return res.status(403).json({

          error:
            'Unauthorized.'

        });

      }


      const total =
        await DriveSync.countDocuments();


      const indexed =
        await DriveSync.countDocuments({

          status:
            'indexed'

        });


      const updated =
        await DriveSync.countDocuments({

          status:
            'updated'

        });


      const failed =
        await DriveSync.countDocuments({

          status:
            'failed'

        });


      const totalChunks =
        await DriveChunk.countDocuments();


      const recent =
        await DriveSync

          .find()

          .sort({

            lastSyncedAt:
              -1

          })

          .limit(20)

          .select(
            '-__v'
          );


      res.json({

        success:
          true,

        total,

        indexed,

        updated,

        failed,

        totalChunks,

        recent

      });

    }

  )

);


/* =========================================================
   AI SEARCH - GEMINI RAG
========================================================= */

app.post(
  '/ai-search',
  async (req, res) => {

    const cleanQuestion =
      String(req.body?.question || '')
        .trim()
        .replace(/\s+/g, ' ');

    if (!cleanQuestion) {

      return res.status(400).json({
        success: false,
        error: 'Question is required.'
      });

    }


    /*
     * NORMALIZED SEARCH KEY
     */

    const searchKey =
      cleanQuestion.toLowerCase();


    /*
     * PREVENT DUPLICATE REQUEST
     */

    if (activeAiSearches.has(searchKey)) {

      console.log(
        `⏭️ Duplicate AI search ignored: "${cleanQuestion}"`
      );

      return res.status(409).json({

        success: false,

        duplicate: true,

        error:
          'Duplicate search request. Please wait for the current search to complete.'

      });

    }


    activeAiSearches.set(
      searchKey,
      Date.now()
    );


    try {

      console.log(
        `🔎 Question: ${cleanQuestion}`
      );


      /*
       * STEP 1
       * VECTOR SEARCH
       */

      const relevantChunks =
        await searchRelevantChunks(
          cleanQuestion,
          5
        );


      console.log(
        `📚 Retrieved ${relevantChunks.length} relevant chunks`
      );


      /*
       * NO RESULTS
       */

      if (
        !relevantChunks ||
        !relevantChunks.length
      ) {

        return res.json({

          success: true,

          question:
            cleanQuestion,

          answer:
            'கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை.',

          sources: []

        });

      }
/* =========================================================
   TEST KEYWORD SEARCH
========================================================= */

app.post(
  '/keyword-search',
  async (req, res) => {

    try {

      const question =
        String(
          req.body?.question || ''
        ).trim();


      if (!question) {

        return res.status(400).json({

          success: false,

          error:
            'Question is required.'

        });

      }


      const results =
        await searchKeywordChunks(
          question,
          10
        );


      return res.json({

        success: true,

        question,

        count:
          results.length,

        results

      });


    } catch (error) {

      console.error(
        '❌ Keyword search error:',
        error
      );


      return res.status(500).json({

        success: false,

        error:
          'Keyword search failed.'

      });

    }

  }
);
/* =========================================================
   PHASE 2 - KEYWORD SEARCH
========================================================= */

async function searchKeywordChunks(question, limit = 10) {

  const cleanQuestion =
    String(question || '')
      .trim()
      .replace(/\s+/g, ' ');

  if (!cleanQuestion) {
    return [];
  }

  console.log(
    `🔤 Keyword search: ${cleanQuestion}`
  );


  /*
   * Split question into useful search terms
   */

  const terms =
    cleanQuestion
      .split(/\s+/)
      .map(term =>
        term
          .replace(/[^\p{L}\p{N}.-]/gu, '')
          .trim()
      )
      .filter(term => term.length >= 2);


  if (!terms.length) {
    return [];
  }


  /*
   * Escape regex characters
   */

  const escapedTerms =
    terms.map(term =>
      term.replace(
        /[.*+?^${}()|[\]\\]/g,
        '\\$&'
      )
    );


  /*
   * Search ALL important terms.
   *
   * $and means every term should be present.
   */

  const conditions =
    escapedTerms.map(term => ({
      $or: [
        {
          text: {
            $regex: term,
            $options: 'i'
          }
        },
        {
          fileName: {
            $regex: term,
            $options: 'i'
          }
        }
      ]
    }));


  const results =
    await DriveChunk.find({
      $and: conditions
    })
    .select({
      _id: 0,
      driveFileId: 1,
      fileName: 1,
      driveUrl: 1,
      chunkIndex: 1,
      text: 1
    })
    .limit(limit)
    .lean();


  console.log(
    `🔤 Keyword results: ${results.length}`
  );


  results.forEach(
    (item, index) => {

      console.log(
        `🔤 Keyword ${index + 1}:`,
        item.fileName,
        '| chunk:',
        item.chunkIndex
      );

    }
  );


  return results;

}
       
      /*
       * DEBUG RETRIEVED DOCUMENTS
       */

      relevantChunks.forEach(
        (item, index) => {

          console.log(
            `📄 Retrieved ${index + 1}:`,
            item.fileName,
            `| chunk:`,
            item.chunkIndex,
            `| score:`,
            item.score
          );

        }
      );


      /*
       * STEP 2
       * BUILD GEMINI CONTEXT
       */

      const context =
        relevantChunks
          .map(
            (item, index) => {

              return `
==============================
SOURCE DOCUMENT ${index + 1}
==============================

FILE NAME:
${item.fileName}

CHUNK INDEX:
${item.chunkIndex}

DOCUMENT CONTENT:
${item.text}

GOOGLE DRIVE SOURCE:
${item.driveUrl || 'Not available'}

==============================
`;

            }
          )
          .join('\n');


      /*
       * STEP 3
       * GEMINI ANSWER
       */

   const response =
  await generateGeminiAnswer(`
USER QUESTION
=============

${cleanQuestion}


RETRIEVED REVENUE DEPARTMENT DOCUMENTS
======================================

${context}


TASK
====

Answer the user's question using the retrieved document content above.

IMPORTANT:

- Examine ALL retrieved document contents.
- If the answer is present in ANY retrieved document, answer it.
- Do NOT require exact wording.
- Summarize and explain the retrieved content when appropriate.
- Do NOT use outside knowledge.
- Do NOT invent missing information.
- Mention the relevant document name when useful.
`);
      const answer =
        typeof response.text === 'string'
          ? response.text.trim()
          : '';


      console.log(
        '🤖 Gemini answer length:',
        answer.length
      );


      /*
       * STEP 5
       * UNIQUE SOURCES
       *
       * 5 chunks may come from the same PDF.
       * Show that PDF only once.
       */

      const uniqueSources =
        new Map();


      for (
        const item of relevantChunks
      ) {

        const key =
          item.driveFileId ||
          item.driveUrl ||
          item.fileName;


        if (
          !uniqueSources.has(key)
        ) {

          uniqueSources.set(
            key,
            {

              fileName:
                item.fileName,

              driveUrl:
                item.driveUrl,

              score:
                item.score

            }
          );

        }

      }


      const sources =
        Array.from(
          uniqueSources.values()
        );


      /*
       * GEMINI RETURNED NO TEXT
       */

      if (!answer) {

        return res.json({

          success: true,

          question:
            cleanQuestion,

          answer:
            'கிடைக்கப்பெற்ற ஆவணங்களில் இருந்து தெளிவான பதிலை உருவாக்க முடியவில்லை.',

          sources

        });

      }


      /*
       * STEP 6
       * FINAL RESPONSE
       */

      return res.json({

        success: true,

        question:
          cleanQuestion,

        answer,

        sources

      });


    } catch (error) {

      console.error(
        '❌ Gemini RAG error:',
        error
      );
/*
 * GEMINI TEMPORARY UNAVAILABLE
 */

if (
  error?.status === 503 ||
  error?.code === 503 ||
  error?.error?.code === 503
) {

  return res.status(503).json({

    success: false,

    error:
      'Gemini AI service is temporarily unavailable. Please try again shortly.',

    temporaryUnavailable: true

  });

}

      /*
       * GEMINI QUOTA EXCEEDED
       */

      if (
        error?.status === 429 ||
        error?.code === 429 ||
        error?.error?.code === 429
      ) {

        return res.status(429).json({

          success: false,

          error:
            'Gemini daily quota exceeded. Please try again after the quota resets.',

          quotaExceeded: true

        });

      }


      /*
       * OTHER GEMINI/API ERRORS
       */

      return res.status(500).json({

        success: false,

        error:
          'AI search is temporarily unavailable. Please try again later.'

      });


    } finally {

      /*
       * REMOVE ACTIVE SEARCH
       */

      activeAiSearches.delete(
        searchKey
      );

    }

  }
);
/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(
      '❌ Unhandled error:',
      err
    );


    /*
     * Mongoose validation error
     */

    if (
      err.name ===
      'ValidationError'
    ) {

      const messages =
        Object.values(
          err.errors
        )

        .map(
          e =>
            e.message
        )

        .join(
          ', '
        );


      return res.status(400).json({

        error:
          messages

      });

    }


    /*
     * Duplicate key
     */

    if (
      err.code ===
      11000
    ) {

      const field =
        Object.keys(
          err.keyValue || {}
        )[0] ||
        'field';


      const value =
        err.keyValue?.[
          field
        ];


      return res.status(409).json({

        error:
          `"${value}" is already registered for ${field}.`

      });

    }


    res.status(500).json({

      error:
        'Internal server error. Please try again.'

    });

  }
);


/* =========================================================
   SERVER
========================================================= */

const PORT =
  process.env.PORT ||
  3000;


app.listen(
  PORT,
  () => {

    console.log(
      `🚀 Server running on port ${PORT}`
    );

  }
);
