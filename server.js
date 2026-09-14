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
const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
const { createCanvas } = require('@napi-rs/canvas');
const { createWorker } = require('tesseract.js');
const AI_SEARCH_DUPLICATE_WINDOW = 5000;

app.set('trust proxy', 1);


/* =========================================================
   FRONTEND PAGE CATALOGUE
   (mirrors the `pages` object in Revenue_Subjects.html so
   AI search can also surface documents that exist on the
   portal but haven't been chunked/embedded into DriveChunk
   yet. Regenerate data/pages-catalogue.json whenever the
   frontend's `pages` object changes.)
========================================================= */

const PAGE_CATALOGUE_PATH =
  path.join(__dirname, 'data', 'pages-catalogue.json');

let pageCatalogue = [];

try {

  pageCatalogue =
    JSON.parse(
      fs.readFileSync(PAGE_CATALOGUE_PATH, 'utf8')
    );

  console.log(
    `📚 Loaded page catalogue: ${pageCatalogue.length} entries`
  );

} catch (error) {

  console.warn(
    '⚠️ Could not load pages-catalogue.json — catalogue fallback search disabled.',
    error.message
  );

  pageCatalogue = [];
}


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
   NOTE: page-catalogue loading + search now lives in a single
   place — the FRONTEND PAGE CATALOGUE block above (`pageCatalogue`)
   and `searchPageCatalogue()`. The earlier duplicate catalogue
   loader (`catalogue`) and its `searchCatalogue()` function read
   the same pages-catalogue.json a second time and were never
   used for the actual /ai-search response — removed to avoid the
   duplicate file read and duplicate search pass on every request.
========================================================= */
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
  'failed',
  'ocr_required'
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
    'gemini-3.5-flash',
    'gemini-3.1-flash-lite'
  ];

  let lastError = null;

  for (const modelName of modelsToTry) {

    try {

      console.log(
        `🤖 Trying Gemini model: ${modelName}`
      );

      const response = await gemini.models.generateContent({

        model: modelName,

        contents: prompt,

        config: {

          systemInstruction: `

You are an AI assistant for the Tamil Nadu Revenue Department portal.

Answer ONLY from the retrieved documents supplied in the prompt.

STRICT RULES:

1. Use retrieved document content as the factual source.

2. If the answer is present in ANY retrieved document,
   you MUST answer the question.

3. Do not say:
   "கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை."
   when the retrieved documents actually contain the answer.

4. Do not require exact wording to appear in the document.

5. You may summarize, translate and explain the retrieved content.

6. Do not invent Government Orders.

7. Do not invent G.O. numbers.

8. Do not invent dates.

9. Do not invent Acts.

10. Do not invent Rules.

11. Do not invent Sections.

12. Do not invent proceedings.

13. Do not invent circular numbers.

14. Do not use outside knowledge.

15. If multiple retrieved documents are relevant,
    combine them carefully into ONE coherent answer.

16. If information is partial,
    clearly state what information is available and what is missing.

17. Only say:
    "கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை."
    when NONE of the retrieved documents contains the answer.

18. If the question is in Tamil, answer in Tamil.

19. If the question is in English, answer in English.

20. If the question mixes Tamil and English,
    answer mainly in the language used most in the question.

21. Mention the relevant document name and G.O. number when useful.

22. Do not just list document titles.
    Explain the relevant content.

23. Preserve exact G.O. numbers, dates, Acts, Rules,
    Sections and Forms exactly as found in the documents.

24. Never guess a missing digit or date.

25. If a retrieved document directly answers the question,
    prioritize that document even if other retrieved documents
    are unrelated.

26. Keep the answer focused and readable.

27. For Government Orders, whenever possible give:
    - G.O. Number
    - Date
    - Subject / purpose
    - Relevant provision
    - Authority / procedure, if available in the document.

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
       * Temporary / unavailable models
       */

      if (
        status === 429 ||
        status === 503 ||
        status === 404
      ) {

        console.log(
          `🔄 ${modelName} unavailable (${status}). Trying next model...`
        );

        continue;
      }

      /*
       * Other errors:
       * Do not silently switch models.
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

  /*
   * Keep the original error available for logging,
   * but return a controlled error to the API layer.
   */

  const controlledError = new Error(
    'Gemini answer generation is temporarily unavailable.'
  );

  controlledError.status = 503;
  controlledError.originalError = lastError;

  throw controlledError;
}
/* =========================================================
   INDEX ONE PDF
========================================================= */

/* =========================================================
   INDEX ONE PDF
========================================================= */

async function indexDrivePdf(file) {
const fileName = file.name;
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

let text =
  pdfData.text || '';


/*
 * NORMAL PDF TEXT EXTRACTION
 */

if (text.trim()) {

  console.log(
    `✅ Text extracted normally: ${file.name} | ${text.length} characters`
  );

}


/*
 * OCR FALLBACK
 *
 * If normal PDF extraction returns no text,
 * try OCR for scanned/image PDFs.
 */

if (!text || !text.trim()) {

  console.log(
    `⚠️ No text found: ${fileName}`
  );

  await DriveSyncFile.updateOne(
    {
      driveFileId: file.driveFileId
    },
    {
      $set: {
        status: 'ocr_required',
        error: 'PDF contains no extractable text. Manual text entry required.'
      }
    }
  );

  console.log(
    `📝 OCR required: ${fileName}`
  );

  return {
    success: true,
    skipped: true,
    ocrRequired: true
  };
}
 if (!text || !text.trim()) {

  console.log(
    `⚠️ No text found: ${fileName}`
  );

  await DriveSyncFile.updateOne(
    {
      driveFileId: file.driveFileId
    },
    {
      $set: {
        status: 'ocr_required',
        error:
          'PDF contains no extractable text. Manual text entry required.'
      }
    }
  );

  console.log(
    `📝 OCR required: ${fileName}`
  );

  return {
    success: true,
    skipped: true,
    ocrRequired: true
  };
}

/*
 * FINAL CHECK
 *
 * If both normal extraction and OCR
 * failed, mark the PDF as failed.
 */

if (!text || !text.trim()) {

  console.log(
    `❌ No usable text after PDF extraction + OCR: ${file.name}`
  );

  return {

    success: false,

    reason:
      'No text found in PDF even after OCR.'

  };

}


/*
 * CLEAN TEXT
 */

text =
  text
    .replace(/\r/g, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();


console.log(
  `📄 Final text length: ${text.length} characters`
);

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

    const drive =
      getGoogleDriveClient();

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

  const indexResult =
  await indexDrivePdf({
    id: file.data.id,
    name: file.data.name,
    modifiedTime: file.data.modifiedTime,
    md5Checksum: file.data.md5Checksum,
    webViewLink: file.data.webViewLink
  });

if (indexResult?.ocrRequired) {

  console.log(
    `📝 Manual text required: ${fileName}`
  );

  await DriveSyncFile.updateOne(
    {
      driveFileId
    },
    {
      $set: {
        status: 'ocr_required',
        error:
          'PDF contains no extractable text. Manual text entry required.',
        completedAt: null
      }
    }
  );

  return {
    success: true,
    skipped: true,
    ocrRequired: true
  };
}

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


  /*
   * Scan Google Drive and register
   * any new PDF files.
   *
   * Do this only for normal sync.
   */

/*  if (!retryFailed) {

    await registerAllDrivePdfFiles();

  }*/


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
   REGISTER ALL GOOGLE DRIVE PDF FILES
   Google Drive → drivesyncfiles
========================================================= */

async function registerAllDrivePdfFiles() {

  console.log('');
  console.log('==========================================');
  console.log('📂 SCANNING GOOGLE DRIVE FOR ALL PDF FILES');
  console.log('==========================================');

  const folderId =
    process.env.GOOGLE_DRIVE_FOLDER_ID;

  if (!folderId) {
    throw new Error(
      'GOOGLE_DRIVE_FOLDER_ID is not configured.'
    );
  }

  console.log(
    '📁 Root Folder ID:',
    folderId
  );

  // ==========================================
  // GOOGLE DRIVE AUTHENTICATION
  // ==========================================

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

  const drive =
    google.drive({
      version: 'v3',
      auth
    });

  // ==========================================
  // COUNTERS
  // ==========================================

  let totalDrivePDFs = 0;

  let existingFiles = 0;

  let newFiles = 0;

  let modifiedFiles = 0;

  let foldersScanned = 0;

  // ==========================================
  // TRACK VISITED FOLDERS
  // Prevent infinite loops
  // ==========================================

  const visitedFolders =
    new Set();

  // ==========================================
  // RECURSIVE FOLDER SCANNER
  // ==========================================

  async function scanFolder(
    currentFolderId,
    currentFolderName = 'Root'
  ) {

    if (
      visitedFolders.has(
        currentFolderId
      )
    ) {

      console.log(
        '⚠️ Folder already scanned:',
        currentFolderName
      );

      return;
    }

    visitedFolders.add(
      currentFolderId
    );

    foldersScanned++;

    console.log('');
    console.log(
      '📁 Scanning folder:',
      currentFolderName
    );

    console.log(
      '🆔 Folder ID:',
      currentFolderId
    );

    let pageToken = null;

    do {

      console.log(
        '🔎 Reading Google Drive page...'
      );

      const response =
        await drive.files.list({

          q:
            `'${currentFolderId}' in parents and trashed = false`,

          fields:
            'nextPageToken,files(id,name,mimeType,modifiedTime,md5Checksum)',

          pageSize:
            1000,

          pageToken:
            pageToken || undefined

        });

      const files =
        response.data.files || [];

      console.log(
        '📄 Items found in this page:',
        files.length
      );

      for (
        const file of files
      ) {

        // ======================================
        // FOLDER
        // ======================================

        if (
          file.mimeType ===
          'application/vnd.google-apps.folder'
        ) {

          console.log('');
          console.log(
            '📁 Sub-folder found:',
            file.name
          );

          await scanFolder(
            file.id,
            file.name
          );

          continue;
        }

        // ======================================
        // PDF ONLY
        // ======================================

        if (
          file.mimeType !==
          'application/pdf'
        ) {

          console.log(
            '⏭️ Skipping non-PDF:',
            file.name,
            '|',
            file.mimeType
          );

          continue;
        }

        // ======================================
        // PDF FOUND
        // ======================================

        totalDrivePDFs++;

        console.log('');
        console.log(
          '📄 PDF FOUND:',
          file.name
        );

        console.log(
          '🆔',
          file.id
        );

        // ======================================
        // CHECK EXISTING RECORD
        // ======================================

        const existing =
          await DriveSyncFile.findOne({

            driveFileId:
              file.id

          });

        // ======================================
        // NEW PDF
        // ======================================

        if (!existing) {

          await DriveSyncFile.create({

            driveFileId:
              file.id,

            fileName:
              file.name,

            modifiedTime:
              file.modifiedTime || '',

            md5Checksum:
              file.md5Checksum || '',

            status:
              'pending',

            error:
              '',

            attempts:
              0,

            lastAttemptAt:
              null,

            completedAt:
              null

          });

          newFiles++;

          console.log(
            '➕ NEW PDF REGISTERED:',
            file.name
          );

          continue;
        }

        // ======================================
        // EXISTING PDF
        // ======================================

        existingFiles++;

        console.log(
          '✔️ Existing PDF:',
          file.name
        );

        // ======================================
        // CHECK WHETHER FILE CHANGED
        // ======================================

        const modifiedTimeChanged =
          (
            existing.modifiedTime || ''
          ) !==
          (
            file.modifiedTime || ''
          );

        const md5Changed =
          (
            existing.md5Checksum || ''
          ) !==
          (
            file.md5Checksum || ''
          );

        if (
          modifiedTimeChanged ||
          md5Changed
        ) {

          console.log(
            '🔄 PDF changed:',
            file.name
          );

          await DriveSyncFile.updateOne(

            {
              driveFileId:
                file.id
            },

            {
              $set: {

                fileName:
                  file.name,

                modifiedTime:
                  file.modifiedTime || '',

                md5Checksum:
                  file.md5Checksum || '',

                status:
                  'pending',

                error:
                  '',

                completedAt:
                  null

              }

            }

          );

          modifiedFiles++;

          console.log(
            '♻️ Marked as pending:',
            file.name
          );

        }

      }

      pageToken =
        response.data.nextPageToken ||
        null;

    } while (pageToken);

  }

  // ==========================================
  // START RECURSIVE SCAN
  // ==========================================

  await scanFolder(
    folderId,
    'ROOT FOLDER'
  );

  // ==========================================
  // FINAL DATABASE COUNTS
  // ==========================================

  const totalTracked =
    await DriveSyncFile.countDocuments();

  const pendingCount =
    await DriveSyncFile.countDocuments({
      status: 'pending'
    });

  const completedCount =
    await DriveSyncFile.countDocuments({
      status: 'completed'
    });

  const failedCount =
    await DriveSyncFile.countDocuments({
      status: 'failed'
    });

  // ==========================================
  // FINAL LOG
  // ==========================================

  console.log('');
  console.log('==========================================');
  console.log('📊 DRIVE SCAN COMPLETED');
  console.log('==========================================');

  console.log(
    '📁 Folders scanned :',
    foldersScanned
  );

  console.log(
    '📄 Google Drive PDFs :',
    totalDrivePDFs
  );

  console.log(
    '✔️ Existing records  :',
    existingFiles
  );

  console.log(
    '➕ New files added   :',
    newFiles
  );

  console.log(
    '🔄 Modified files    :',
    modifiedFiles
  );

  console.log(
    '📚 Total tracked     :',
    totalTracked
  );

  console.log(
    '⏳ Pending            :',
    pendingCount
  );

  console.log(
    '✅ Completed          :',
    completedCount
  );

  console.log(
    '❌ Failed             :',
    failedCount
  );

  console.log(
    '==========================================');

  return {

    totalDrivePDFs,

    existingFiles,

    newFiles,

    modifiedFiles,

    foldersScanned,

    totalTracked,

    pendingCount,

    completedCount,

    failedCount

  };

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
   REPAIR EMPTY GEMINI EMBEDDINGS
========================================================= */

/* =========================================================
   REPAIR EMPTY GEMINI EMBEDDINGS
========================================================= */

async function repairEmptyEmbeddings(batchSize = 5) {

  console.log('');
  console.log(
    '=========================================='
  );

  console.log(
    `🔧 REPAIR EMPTY EMBEDDINGS: ${batchSize} CHUNKS`
  );

  console.log(
    '=========================================='
  );


  /*
   * Find only chunks with empty/missing embeddings
   */

  const chunks =
    await DriveChunk.find({

      $or: [

        {
          embedding: {
            $size: 0
          }
        },

        {
          embedding: {
            $exists: false
          }
        }

      ]

    })
    .limit(batchSize)
    .lean();


  if (!chunks.length) {

    console.log(
      '✅ No empty embeddings found.'
    );

    return {

      processed: 0,
      success: 0,
      failed: 0,
      remaining: 0,
      quotaExceeded: false

    };
  }


  console.log(
    `📚 Empty chunks found in this batch: ${chunks.length}`
  );


  let success = 0;
  let failed = 0;
  let quotaExceeded = false;


  /*
   * Process chunks one by one
   */

  for (
    let i = 0;
    i < chunks.length;
    i++
  ) {

    const chunk =
      chunks[i];


    console.log('');
    console.log(
      `🔢 Repair ${i + 1}/${chunks.length}`
    );


    console.log(
      `📄 File: ${
        chunk.fileName ||
        chunk.name ||
        'Unknown'
      }`
    );


    console.log(
      `🆔 Chunk ID: ${chunk._id}`
    );


    /*
     * Safety check
     *
     * Never overwrite an existing
     * valid 768-dimensional embedding.
     */

    if (
      Array.isArray(chunk.embedding) &&
      chunk.embedding.length === 768
    ) {

      console.log(
        '⏭️ Valid 768 embedding already exists. Skipping.'
      );

      continue;
    }


    /*
     * Get chunk text
     */

    const text =
      chunk.text ||
      chunk.content ||
      '';


    if (!text.trim()) {

      console.log(
        '⚠️ Chunk has no text. Skipping.'
      );

      failed++;

      continue;
    }


    try {

      /*
       * =====================================
       * USE YOUR EXISTING GEMINI FUNCTION
       * =====================================
       */

      console.log(
        '🧠 Generating Gemini embedding...'
      );


      const embedding =
        await createDocumentEmbedding(
          text
        );


      /*
       * createDocumentEmbedding()
       * already validates:
       *
       * 768 dimensions
       */

      if (
        !Array.isArray(embedding) ||
        embedding.length !== 768
      ) {

        throw new Error(
          `Invalid embedding dimension: ${
            embedding?.length || 0
          }`
        );
      }


      console.log(
        `✅ Embedding generated: ${embedding.length} dimensions`
      );


      /*
       * =====================================
       * UPDATE ONLY EMPTY CHUNK
       * =====================================
       */

      const updateResult =
        await DriveChunk.updateOne(

          {
            _id: chunk._id,

            /*
             * IMPORTANT:
             * Only update if still empty.
             */

            $or: [

              {
                embedding: {
                  $size: 0
                }
              },

              {
                embedding: {
                  $exists: false
                }
              }

            ]

          },

          {
            $set: {
              embedding: embedding
            }
          }

        );


      if (
        updateResult.modifiedCount === 1
      ) {

        console.log(
          '💾 MongoDB embedding updated successfully.'
        );

        success++;

      } else {

        console.log(
          '⏭️ Chunk was already updated by another process.'
        );

      }


      /*
       * Small delay to reduce rate-limit pressure
       */

      await new Promise(
        resolve =>
          setTimeout(
            resolve,
            1500
          )
      );


    } catch (error) {

      const message =
        error?.message ||
        'Unknown Gemini error';


      /*
       * =====================================
       * GEMINI QUOTA / RATE LIMIT
       * =====================================
       */

      if (

        error?.status === 429 ||

        error?.code === 429 ||

        message.includes(
          '429'
        ) ||

        message.includes(
          'RESOURCE_EXHAUSTED'
        ) ||

        message.toLowerCase().includes(
          'quota'
        )

      ) {

        console.error(
          '🚫 Gemini quota exceeded.'
        );

        console.error(
          message
        );


        quotaExceeded = true;

        failed++;


        /*
         * STOP immediately.
         */

        break;
      }


      console.error(
        `❌ Embedding repair failed: ${message}`
      );


      failed++;
    }

  }


  /*
   * Count remaining empty embeddings
   */

  const remaining =
    await DriveChunk.countDocuments({

      $or: [

        {
          embedding: {
            $size: 0
          }
        },

        {
          embedding: {
            $exists: false
          }
        }

      ]

    });


  console.log('');
  console.log(
    '=========================================='
  );

  console.log(
    '🔧 REPAIR COMPLETE'
  );

  console.log(
    `Processed : ${chunks.length}`
  );

  console.log(
    `Success   : ${success}`
  );

  console.log(
    `Failed    : ${failed}`
  );

  console.log(
    `Remaining : ${remaining}`
  );


  if (quotaExceeded) {

    console.log(
      '🚫 Stopped because Gemini quota was exceeded.'
    );

  }


  console.log(
    '=========================================='
  );


  return {

    processed:
      chunks.length,

    success,

    failed,

    remaining,

    quotaExceeded

  };

}
/* =========================================================
   REPAIR EMPTY EMBEDDINGS
========================================================= */
app.post(
  '/admin/repair-empty-embeddings',
  async (req, res) => {

    try {

      const requestedSize =
        Number(
          req.body?.batchSize
        ) || 5;


      const batchSize =
        Math.min(
          Math.max(
            requestedSize,
            1
          ),
          20
        );


      const result =
        await repairEmptyEmbeddings(
          batchSize
        );


      res.json({

        success: true,

        mode:
          'repair-empty-embeddings',

        result

      });


    } catch (error) {

      console.error(
        '❌ Repair empty embeddings error:',
        error
      );


      res.status(500).json({

        success: false,

        error:
          error.message

      });

    }

  }
);
/* =========================================================
   BATCH SYNC API
========================================================= */


/*
 * GET SYNC STATUS
 */
// =====================================================
// OCR REQUIRED FILES - LIST
// =====================================================

app.get(
  '/admin/drive-sync/ocr-required',
  async (req, res) => {

    try {

      const files =
        await DriveSyncFile.find({
          status: 'ocr_required'
        })
        .sort({ updatedAt: -1 })
        .lean();

      res.json({
        success: true,
        count: files.length,
        files
      });

    } catch (error) {

      console.error(
        'OCR required list error:',
        error
      );

      res.status(500).json({
        success: false,
        error: error.message
      });

    }

  }
);
// =====================================================
// MANUAL TEXT ENTRY
// TEXT → CHUNKS → GEMINI EMBEDDINGS → MONGODB
// =====================================================

app.post(
  '/admin/drive-sync/manual-text',
  async (req, res) => {

    try {

      const {
        driveFileId,
        text
      } = req.body;

      // -----------------------------------------------
      // VALIDATION
      // -----------------------------------------------

      if (!driveFileId) {

        return res.status(400).json({
          success: false,
          error: 'driveFileId is required.'
        });

      }

      if (!text || !text.trim()) {

        return res.status(400).json({
          success: false,
          error: 'Manual text is required.'
        });

      }

      const cleanText =
        text
          .replace(/\r\n/g, '\n')
          .replace(/\r/g, '\n')
          .trim();

      console.log('');
      console.log(
        '=========================================='
      );
      console.log(
        '📝 MANUAL TEXT INDEXING'
      );
      console.log(
        '=========================================='
      );

      console.log(
        `🆔 Drive File ID: ${driveFileId}`
      );

      console.log(
        `📝 Text length: ${cleanText.length}`
      );


      // -----------------------------------------------
      // FIND DRIVE FILE
      // -----------------------------------------------

      const syncFile =
        await DriveSyncFile.findOne({
          driveFileId
        });

      if (!syncFile) {

        return res.status(404).json({
          success: false,
          error: 'Drive sync file not found.'
        });

      }


      // -----------------------------------------------
      // CREATE CHUNKS
      // -----------------------------------------------

      const chunkSize = 5000;
      const overlap = 500;

      const chunks = [];

      let start = 0;

      while (start < cleanText.length) {

        const end =
          Math.min(
            start + chunkSize,
            cleanText.length
          );

        const chunk =
          cleanText
            .slice(start, end)
            .trim();

        if (chunk) {
          chunks.push(chunk);
        }

        if (end >= cleanText.length) {
          break;
        }

        start =
          end - overlap;
      }

      console.log(
        `📚 ${chunks.length} chunks created`
      );


      if (!chunks.length) {

        return res.status(400).json({
          success: false,
          error: 'No usable text chunks created.'
        });

      }


      // -----------------------------------------------
      // CREATE ALL EMBEDDINGS FIRST
      // -----------------------------------------------

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

        newChunks.push({
          driveFileId: syncFile.driveFileId,

          fileName: syncFile.fileName,

          chunkIndex: i,

          text: chunks[i],

          embedding: embedding,

          modifiedTime:
            syncFile.modifiedTime,

          md5Checksum:
            syncFile.md5Checksum,

          source:
            'manual'
        });

      }


      // -----------------------------------------------
      // DELETE OLD CHUNKS ONLY AFTER
      // ALL EMBEDDINGS ARE SUCCESSFUL
      // -----------------------------------------------

      await DriveChunk.deleteMany({
        driveFileId
      });

      console.log(
        '🗑️ Old chunks removed'
      );


      // -----------------------------------------------
      // INSERT NEW CHUNKS
      // -----------------------------------------------

      await DriveChunk.insertMany(
        newChunks
      );

      console.log(
        `💾 ${newChunks.length} chunks inserted`
      );


      // -----------------------------------------------
      // UPDATE SYNC STATUS
      // -----------------------------------------------

      await DriveSyncFile.updateOne(
        {
          driveFileId
        },
        {
          $set: {
            status: 'completed',

            error: '',

            completedAt:
              new Date(),

            lastAttemptAt:
              new Date()
          }
        }
      );


      console.log(
        `✅ Manual text indexing completed: ${syncFile.fileName}`
      );


      res.json({

        success: true,

        message:
          'Manual text indexed successfully.',

        fileName:
          syncFile.fileName,

        chunks:
          newChunks.length,

        dimensions: 768,

        status:
          'completed'

      });


    } catch (error) {

      console.error('');
      console.error(
        '❌ Manual text indexing failed'
      );
      console.error(
        error.message
      );


      // -----------------------------------------------
      // KEEP FILE AS OCR REQUIRED
      // -----------------------------------------------

      if (req.body?.driveFileId) {

        await DriveSyncFile.updateOne(
          {
            driveFileId:
              req.body.driveFileId
          },
          {
            $set: {
              status:
                'ocr_required',

              error:
                String(
                  error.message || error
                ).substring(
                  0,
                  2000
                )
            }
          }
        );

      }


      res.status(500).json({

        success: false,

        error:
          error.message

      });

    }

  }
);
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
 * LIST FAILED FILES WITH THEIR ERROR REASON
 * (so you don't have to scroll Render logs to see why)
 */

app.get(
  '/admin/drive-sync/failed',
  async (req, res) => {

    try {

      const failedFiles =
        await DriveSyncFile.find(
          { status: 'failed' }
        )
        .sort({ lastAttemptAt: -1 })
        .select(
          'driveFileId fileName error attempts lastAttemptAt'
        )
        .lean();

      res.json({
        success: true,
        count: failedFiles.length,
        failedFiles
      });

    } catch (error) {

      console.error(
        'List failed files error:',
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


/*
 * REGISTER FRONTEND CATALOGUE FILES FOR INDEXING
 *
 * Queues every Drive file referenced in the frontend's
 * pages{} catalogue (data/pages-catalogue.json) that isn't
 * already tracked, so the normal /admin/drive-sync/batch
 * loop will chunk + embed it over time. This does NOT do
 * the indexing itself — call /admin/drive-sync/batch
 * afterwards (repeatedly) to actually process the queue.
 */

app.post(
  '/admin/drive-sync/register-catalogue',
  async (req, res) => {

    const suppliedSecret =
      req.headers['x-sync-secret'];

    if (
      !process.env.DRIVE_SYNC_SECRET ||
      suppliedSecret !== process.env.DRIVE_SYNC_SECRET
    ) {

      return res.status(403).json({
        error: 'Unauthorized.'
      });
    }

    try {

      if (!pageCatalogue.length) {

        return res.json({
          success: true,
          checked: 0,
          registered: 0,
          message: 'Page catalogue is empty or not loaded.'
        });
      }

      const drive =
        getGoogleDriveClient();

      const uniqueIds =
        Array.from(
          new Set(
            pageCatalogue
              .map(item => item.driveFileId)
              .filter(Boolean)
          )
        );

      const existing =
        await DriveSyncFile.find(
          { driveFileId: { $in: uniqueIds } },
          { driveFileId: 1, _id: 0 }
        ).lean();

      const existingIds =
        new Set(existing.map(f => f.driveFileId));

      const newIds =
        uniqueIds.filter(id => !existingIds.has(id));

      const toRegister = [];
      const metadataErrors = [];

      for (const id of newIds) {

        try {

          const file =
            await drive.files.get({
              fileId: id,
              fields:
                'id,name,mimeType,modifiedTime,md5Checksum'
            });

          if (
            file.data &&
            file.data.mimeType === 'application/pdf'
          ) {

            toRegister.push({
              id: file.data.id,
              name: file.data.name,
              modifiedTime: file.data.modifiedTime,
              md5Checksum: file.data.md5Checksum
            });
          }

        } catch (err) {

          metadataErrors.push({
            driveFileId: id,
            error: err.message
          });
        }

        // Small delay — gentle on the Drive API.
        await new Promise(
          resolve => setTimeout(resolve, 150)
        );
      }

      if (toRegister.length) {
        await registerDriveFiles(toRegister);
      }

      res.json({

        success: true,

        catalogueFiles:
          uniqueIds.length,

        alreadyTracked:
          existingIds.size,

        newlyRegistered:
          toRegister.length,

        metadataErrors

      });

    } catch (error) {

      console.error(
        'Register catalogue error:',
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
   PHASE 2 - KEYWORD SEARCH
========================================================= */

async function searchKeywordChunks(question, limit = 10, fileIds = []) {

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

  // ==================================================
  // 1. Extract special legal / government references
  // ==================================================

  const specialTerms = [];

  // G.O.175
  // G.O. 175
  // G.O.Ms.No.175
  // G.O.(Ms) No.175
  // GO 175
  // GOMS 175

  const goMatches =
    cleanQuestion.match(
      /\bG\.?\s*O\.?\s*(?:\(\s*(?:Ms|D|Ord)\s*\))?\s*(?:Ms\.?\s*)?(?:No\.?\s*)?\.?\s*\d+(?:\/\d+)?/gi
    );

  if (goMatches) {

    for (const match of goMatches) {

      const normalized =
        match
          .replace(/\s+/g, '')
          .replace(/\(\s*/g, '(')
          .replace(/\s*\)/g, ')')
          .toLowerCase();

      specialTerms.push(normalized);

      // Also extract the numerical G.O. number
      const numberMatch =
        match.match(/\d+(?:\/\d+)?/);

      if (numberMatch) {
        specialTerms.push(
          `go${numberMatch[0]}`
        );

        specialTerms.push(
          numberMatch[0]
        );
      }
    }
  }

  // ==================================================
  // 2. Section numbers
  // ==================================================

  const sectionMatches =
    cleanQuestion.match(
      /\b(?:section|sec\.?)\s*\d+(?:-[a-z])?(?:\([a-z0-9]+\))?/gi
    );

  if (sectionMatches) {

    for (const match of sectionMatches) {

      specialTerms.push(
        match
          .replace(/\s+/g, '')
          .toLowerCase()
      );

    }
  }

  // ==================================================
  // 3. Rule numbers
  // ==================================================

  const ruleMatches =
    cleanQuestion.match(
      /\b(?:rule|rules)\s*\d+(?:\([a-z0-9]+\))?/gi
    );

  if (ruleMatches) {

    for (const match of ruleMatches) {

      specialTerms.push(
        match
          .replace(/\s+/g, '')
          .toLowerCase()
      );

    }
  }

  // ==================================================
  // 4. Date detection
  // ==================================================

  const dateMatches =
    cleanQuestion.match(
      /\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b/g
    );

  if (dateMatches) {

    for (const date of dateMatches) {
      specialTerms.push(date);
    }
  }

  // ==================================================
  // 5. Normal keyword extraction
  // ==================================================

  const rawTerms =
    cleanQuestion
      .split(/\s+/)
      .map(term =>
        term
          .replace(
            /[^\p{L}\p{N}\p{M}.-]/gu,
            ''
          )
          .trim()
      )
      .filter(
        term =>
          term.length >= 3
      );

  // ==================================================
  // 6. Tamil question words to ignore
  // ==================================================

 const stopWords = new Set([

  'எதை',
  'எது',
  'என்ன',
  'எப்படி',
  'எங்கே',
  'எப்போது',
  'எதற்கு',
  'எதனால்',
  'எதற்காக',
  'யார்',
  'யாருடைய',
  'யாருக்கு',
  'யாரால்',
  'எந்த',
  'எவ்வாறு',
  'எவ்வளவு',
  'எத்தனை',
  'குறித்து',
  'பற்றி',
  'கூறுகிறது',
  'கூறுக',
  'விளக்குக',
  'விளக்கவும்',
  'விளக்கம்',
  'சொல்லவும்',
  'தெரிவிக்கவும்',
  'உள்ளது',
  'உள்ளன',
  'ஆகும்',
  'என்பது',

  'what',
  'which',
  'when',
  'where',
  'why',
  'who',
  'how',
  'about',
  'tell',
  'explain',
  'please',
  'give',
  'details',
  'detail',
  'does',
  'mean',
  'means'

]);
  const normalTerms =
    rawTerms
      .map(term =>
        term.toLowerCase()
      )
      .filter(
        term =>
          !stopWords.has(term)
      );

  // ==================================================
  // 7. Combine special + normal terms
  // ==================================================

  const allTerms =
    [
      ...specialTerms,
      ...normalTerms
    ];

  const uniqueTerms =
    [
      ...new Set(
        allTerms.filter(
          term => term && term.length >= 2
        )
      )
    ];

  if (!uniqueTerms.length) {

    console.log(
      '🔤 No useful keyword terms found'
    );

    return [];
  }

  console.log(
    '🔤 Search terms:',
    uniqueTerms
  );

  // ==================================================
  // 8. Build regex
  // ==================================================

  const regexTerms =
    uniqueTerms.map(term =>
      term.replace(
        /[.*+?^${}()|[\]\\]/g,
        '\\$&'
      )
    );

  const regex =
    regexTerms.join('|');

  // ==================================================
  // 9. MongoDB keyword search
  // ==================================================

  const keywordQuery = {

    $or: [

      {
        text: {
          $regex: regex,
          $options: 'i'
        }
      },

      {
        fileName: {
          $regex: regex,
          $options: 'i'
        }
      }

    ]

  };

  // Scope to a specific category's files, when the frontend
  // has one open (window.currentAIFileIds).
  if (Array.isArray(fileIds) && fileIds.length) {
    keywordQuery.driveFileId = { $in: fileIds };
  }

  const results =
    await DriveChunk.find(keywordQuery)
    .select({

      _id: 0,

      driveFileId: 1,

      fileName: 1,

      driveUrl: 1,

      chunkIndex: 1,

      text: 1

    })
    .limit(200)
    .lean();

  console.log(
    `🔤 Keyword raw matches: ${results.length}`
  );

  // ==================================================
  // 10. Score results
  // ==================================================

  // ==================================================
// 10. Score results
// ==================================================

const scoredResults =
  results.map(item => {

    const fileName =
      String(
        item.fileName || ''
      ).toLowerCase();

    const text =
      String(
        item.text || ''
      ).toLowerCase();

    const lowerQuestion =
      cleanQuestion.toLowerCase();

    let keywordScore = 0;

    const matchedTerms = [];

    // ==============================================
    // Count normal keyword matches
    // ==============================================

    let normalMatchedCount = 0;

    const matchedNormalTerms = [];

    for (const term of uniqueTerms) {

      const termLower =
        term.toLowerCase();

      const inFileName =
        fileName.includes(termLower);

      const inText =
        text.includes(termLower);

      // ==========================================
      // Special legal references
      // ==========================================

      const isSpecial =
        specialTerms.includes(term);

      if (isSpecial) {

        if (inFileName) {

          keywordScore += 15;

          matchedTerms.push(term);

        }

        else if (inText) {

          keywordScore += 10;

          matchedTerms.push(term);

        }

        continue;
      }

      // ==========================================
      // Normal keywords
      // ==========================================

      if (inFileName) {

        // Filename match is strong
        keywordScore += 4;

        normalMatchedCount++;

        matchedNormalTerms.push(term);

        matchedTerms.push(term);

      }

      else if (inText) {

        keywordScore += 1;

        normalMatchedCount++;

        matchedNormalTerms.push(term);

        matchedTerms.push(term);

      }

    }

    // ==============================================
    // IMPORTANT:
    // Multiple important keywords in same document
    // ==============================================

    if (
      normalMatchedCount >= 2
    ) {

      keywordScore +=
        normalMatchedCount * 3;

    }

    // ==============================================
    // Exact phrase bonus
    // ==============================================

    // Only use meaningful normal terms
    // instead of the complete Tamil question.

    const meaningfulTerms =
      normalTerms.filter(
        term =>
          term.length >= 3
      );

    if (
      meaningfulTerms.length >= 2
    ) {

      const phrase =
        meaningfulTerms.join(' ');

      if (
        fileName.includes(phrase)
      ) {

        keywordScore += 12;

      }

      if (
        text.includes(phrase)
      ) {

        keywordScore += 8;

      }

    }

    // ==============================================
    // Exact question phrase bonus
    // ==============================================

    if (
      lowerQuestion.length >= 8 &&
      text.includes(lowerQuestion)
    ) {

      keywordScore += 10;

    }

    // ==============================================
    // Exact G.O. number bonus
    // ==============================================

    for (
      const specialTerm
      of specialTerms
    ) {

      if (
        text.includes(
          specialTerm
        )
      ) {

        keywordScore += 20;

      }

      if (
        fileName.includes(
          specialTerm
        )
      ) {

        keywordScore += 30;

      }

    }

    return {

      ...item,

      keywordScore,

      matchedTerms:
        [
          ...new Set(
            matchedTerms
          )
        ]

    };

  });
  // ==================================================
  // 11. Remove zero-score results
  // ==================================================

  const validResults =
    scoredResults.filter(
      item =>
        item.keywordScore > 0
    );

  // ==================================================
  // 12. Sort
  // ==================================================

  validResults.sort(
    (a, b) =>
      b.keywordScore -
      a.keywordScore
  );

  // ==================================================
  // 13. Final results
  // ==================================================

  const finalResults =
    validResults.slice(
      0,
      limit
    );

  console.log(
    `🔤 Keyword results: ${finalResults.length}`
  );

  finalResults.forEach(
    (item, index) => {

      console.log(
        `🔤 Keyword ${index + 1}:`,
        item.fileName,
        '| chunk:',
        item.chunkIndex,
        '| score:',
        item.keywordScore,
        '| matched:',
        item.matchedTerms.join(', ')
      );

    }
  );

  return finalResults;
}


/* =========================================================
   PAGE CATALOGUE TITLE SEARCH
   (fallback over the frontend's pages{} list — no document
   body text, title/link only)
========================================================= */

/*
 * Common connector / question words that appear in almost every
 * Tamil or English query. Kept separate from the stopWords set in
 * searchKeywordChunks() (that one is scoped inside that function)
 * so this titles-only fallback doesn't treat "வேண்டும்", "பற்றி",
 * "details" etc. as if they were meaningful search terms — a
 * single connector-word match was matching many unrelated PDF
 * titles and flooding the sources list.
 */
const PAGE_CATALOGUE_STOP_WORDS = new Set([

  'எதை', 'எது', 'என்ன', 'எப்படி', 'எங்கே', 'எப்போது', 'எதற்கு',
  'எதனால்', 'எதற்காக', 'யார்', 'யாருடைய', 'யாருக்கு', 'யாரால்',
  'எந்த', 'எவ்வாறு', 'எவ்வளவு', 'எத்தனை', 'குறித்து', 'பற்றி',
  'கூறுகிறது', 'கூறுக', 'விளக்குக', 'விளக்கவும்', 'விளக்கம்',
  'சொல்லவும்', 'தெரிவிக்கவும்', 'உள்ளது', 'உள்ளன', 'ஆகும்',
  'என்பது', 'வேண்டும்', 'தேவை', 'தேவையில்லை', 'வழங்க', 'வழங்கவும்',
  'கோரினால்', 'குறித்த', 'ஆவணம்', 'ஆவணங்கள்',

  'what', 'which', 'when', 'where', 'why', 'who', 'how', 'about',
  'tell', 'explain', 'please', 'give', 'details', 'detail',
  'does', 'mean', 'means', 'need', 'required', 'form'

]);

function searchPageCatalogue(question, limit = 3, fileIds = []) {

  const cleanQuestion =
    String(question || '')
      .trim()
      .replace(/\s+/g, ' ');

  if (!cleanQuestion || !pageCatalogue.length) {
    return [];
  }

  const terms =
    cleanQuestion
      .toLowerCase()
      .split(/\s+/)
      .map(term =>
        term
          .replace(/[^\p{L}\p{N}\p{M}.-]/gu, '')
          .trim()
      )
      .filter(
        term =>
          term.length >= 2 &&
          !PAGE_CATALOGUE_STOP_WORDS.has(term)
      );

  if (!terms.length) {
    return [];
  }

  const scoped =
    Array.isArray(fileIds) && fileIds.length > 0
      ? new Set(fileIds)
      : null;

  /*
   * A title is only a genuine match when a real majority of the
   * meaningful search terms appear in it — not just one incidental
   * word — otherwise loosely related titles crowd out the actual
   * document the question is about.
   */

  const requiredMatches =
    Math.max(
      1,
      Math.ceil(terms.length * 0.6)
    );

  const scored = [];

  for (const entry of pageCatalogue) {

    if (scoped && !scoped.has(entry.driveFileId)) {
      continue;
    }

    const haystack =
      `${entry.groupLabel || ''} ${entry.text || ''}`
        .toLowerCase();

    let matches = 0;

    for (const term of terms) {
      if (term && haystack.includes(term)) {
        matches++;
      }
    }

    if (matches >= requiredMatches) {
      scored.push({ ...entry, matchedTerms: matches });
    }
  }

  scored.sort(
    (a, b) => b.matchedTerms - a.matchedTerms
  );

  return scored.slice(0, limit);
}




async function debugExactKeywordSearch(searchTerm) {

  const term =
    String(searchTerm || '')
      .trim();

  if (!term) {
    return [];
  }

  console.log(
    `🧪 DEBUG exact search: ${term}`
  );

  const results =
    await DriveChunk.find({
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
    })
    .select({
      _id: 0,
      driveFileId: 1,
      fileName: 1,
      driveUrl: 1,
      chunkIndex: 1,
      text: 1
    })
    .limit(50)
    .lean();

  console.log(
    `🧪 DEBUG matches for "${term}":`,
    results.length
  );

  results.forEach(
    (item, index) => {

      console.log(
        `🧪 ${index + 1}:`,
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
  limit = 5,
  fileIds = []
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
   *
   * When a category scope (fileIds) is supplied we can't
   * pre-filter inside $vectorSearch without a filterable
   * index field, so we pull a wider candidate pool and
   * filter it down to the requested files afterwards.
   */

  const scoped =
    Array.isArray(fileIds) && fileIds.length > 0;

  const vectorLimit =
    scoped
      ? Math.max(limit * 8, 40)
      : limit;

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
              vectorLimit * 20
            ),

          limit:
            vectorLimit

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


  const fileIdSet =
    scoped ? new Set(fileIds) : null;

  const scopedResults =
    fileIdSet
      ? results.filter(item => fileIdSet.has(item.driveFileId))
      : results;

  const finalResults =
    scopedResults.slice(0, limit);


  console.log(
    `📚 Retrieved ${finalResults.length} relevant chunks` +
    (scoped ? ` (scoped to ${fileIds.length} file(s))` : '')
  );


  return finalResults;

}
function extractLegalReferences(question) {

  const text =
    String(question || '');

  const references = {
    goNumbers: [],
    sections: [],
    rules: [],
    dates: []
  };

  // ==========================================
  // G.O. numbers
  // ==========================================

  const goRegex =
    /\bG\.?\s*O\.?\s*(?:\(\s*(?:Ms|D|Ord)\s*\))?\s*(?:No\.?\s*)?\.?\s*(\d+)(?:\/(\d+))?/gi;

  let match;

  while (
    (match = goRegex.exec(text)) !== null
  ) {

    const number =
      match[1];

    if (number) {

      references.goNumbers.push(
        number
      );

    }
  }

  // ==========================================
  // Section numbers
  // ==========================================

  const sectionRegex =
    /\b(?:section|sec\.?)\s*(\d+(?:-[a-z])?)/gi;

  while (
    (match =
      sectionRegex.exec(text)) !== null
  ) {

    if (match[1]) {

      references.sections.push(
        match[1].toLowerCase()
      );

    }
  }

  // ==========================================
  // Rule numbers
  // ==========================================

  const ruleRegex =
    /\b(?:rule|rules)\s*(\d+(?:\([a-z0-9]+\))?)/gi;

  while (
    (match =
      ruleRegex.exec(text)) !== null
  ) {

    if (match[1]) {

      references.rules.push(
        match[1].toLowerCase()
      );

    }
  }

  // ==========================================
  // Dates
  // ==========================================

  const dateRegex =
    /\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b/g;

  const dateMatches =
    text.match(dateRegex);

  if (dateMatches) {

    references.dates =
      dateMatches;
  }

  // Remove duplicates

  references.goNumbers =
    [...new Set(
      references.goNumbers
    )];

  references.sections =
    [...new Set(
      references.sections
    )];

  references.rules =
    [...new Set(
      references.rules
    )];

  references.dates =
    [...new Set(
      references.dates
    )];

  console.log(
    '⚖️ Legal references:',
    references
  );

  return references;
}
function calculateLegalReferenceScore(
  item,
  references
) {

  const fileName =
    String(
      item.fileName || ''
    ).toLowerCase();

  const text =
    String(
      item.text || ''
    ).toLowerCase();

  let score = 0;

  const matched = [];

  // ==========================================
  // G.O. NUMBER
  // ==========================================

  for (
    const goNumber
    of references.goNumbers
  ) {

    const patterns = [

      `g.o.${goNumber}`,

      `g.o. ${goNumber}`,

      `g.o no.${goNumber}`,

      `g.o. no.${goNumber}`,

      `g.o.ms.no.${goNumber}`,

      `g.o. ms. no. ${goNumber}`,

      `g.o.(ms) no.${goNumber}`,

      `g.o. (ms) no. ${goNumber}`,

      `go${goNumber}`

    ];

    for (
      const pattern
      of patterns
    ) {

      if (
        fileName.includes(pattern)
      ) {

        score += 100;

        matched.push(
          pattern
        );

      }

      if (
        text.includes(pattern)
      ) {

        score += 80;

        matched.push(
          pattern
        );

      }
    }

    // Numerical reference fallback.
    // Only give a small score because
    // "175" alone is not necessarily a G.O.

    const numberRegex =
      new RegExp(
        `\\b${goNumber}\\b`,
        'i'
      );

    if (
      numberRegex.test(text)
    ) {

      score += 10;

      matched.push(
        goNumber
      );

    }
  }

  // ==========================================
  // SECTION
  // ==========================================

  for (
    const section
    of references.sections
  ) {

    const sectionPatterns = [

      `section ${section}`,

      `section${section}`,

      `sec. ${section}`,

      `sec.${section}`

    ];

    for (
      const pattern
      of sectionPatterns
    ) {

      if (
        text.includes(pattern)
      ) {

        score += 80;

        matched.push(
          pattern
        );

      }

    }
  }

  // ==========================================
  // RULE
  // ==========================================

  for (
    const rule
    of references.rules
  ) {

    const rulePatterns = [

      `rule ${rule}`,

      `rule${rule}`,

      `rules ${rule}`

    ];

    for (
      const pattern
      of rulePatterns
    ) {

      if (
        text.includes(pattern)
      ) {

        score += 70;

        matched.push(
          pattern
        );

      }

    }
  }

  // ==========================================
  // DATE
  // ==========================================

  for (
    const date
    of references.dates
  ) {

    if (
      text.includes(
        date.toLowerCase()
      )
    ) {

      score += 60;

      matched.push(
        date
      );

    }
  }

  return {
    score,
    matched:
      [...new Set(matched)]
  };
}
/* =========================================================
   PHASE 3 - HYBRID SEARCH
   KEYWORD + VECTOR
========================================================= */

async function searchHybridChunks(
  question,
  limit = 12,
  fileIds = []
) {

  console.log(
    '🔀 Starting Hybrid Search...' +
    (fileIds && fileIds.length
      ? ` (scoped to ${fileIds.length} file(s))`
      : '')
  );

  // ==========================================
  // Extract legal references
  // ==========================================

  const legalReferences =
    extractLegalReferences(question);

  console.log(
    '⚖️ Legal references:',
    legalReferences
  );

  // ==========================================
  // Run keyword + vector search
  // ==========================================

  const [
    keywordResults,
    vectorResults
  ] = await Promise.all([

    searchKeywordChunks(
      question,
      15,
      fileIds
    ),

    searchRelevantChunks(
      question,
      15,
      fileIds
    )

  ]);

  console.log(
    `🔤 Keyword results: ${keywordResults.length}`
  );

  console.log(
    `🧠 Vector results: ${vectorResults.length}`
  );

  // ==========================================
  // Merge results
  // ==========================================

  const merged =
    new Map();

  // ==========================================
  // KEYWORD RESULTS
  // ==========================================

  keywordResults.forEach(
    item => {

      const key =
        `${item.driveFileId}_${item.chunkIndex}`;

      const legal =
        calculateLegalReferenceScore(
          item,
          legalReferences
        );

      merged.set(
        key,
        {

          ...item,

          keywordScore:
            Number(
              item.keywordScore || 0
            ),

          vectorScore:
            0,

          legalScore:
            Number(
              legal.score || 0
            ),

          matchedLegalReferences:
            legal.matched || [],

          hybridScore:
            (
              Number(
                item.keywordScore || 0
              ) * 0.35
            ) +

            (
              Number(
                legal.score || 0
              ) * 0.50
            )

        }
      );

    }
  );

  // ==========================================
  // VECTOR RESULTS
  // ==========================================

  vectorResults.forEach(
    item => {

      const key =
        `${item.driveFileId}_${item.chunkIndex}`;

      const rawVectorScore =
        Number(
          item.score || 0
        );

      const normalizedVectorScore =
        Math.max(
          0,
          Math.min(
            1,
            rawVectorScore
          )
        );

      if (
        merged.has(key)
      ) {

        const existing =
          merged.get(key);

        existing.vectorScore =
          normalizedVectorScore;

        existing.hybridScore =
          (
            Number(
              existing.keywordScore || 0
            ) * 0.35
          ) +

          (
            Number(
              existing.legalScore || 0
            ) * 0.50
          ) +

          (
            normalizedVectorScore * 0.65
          );

        merged.set(
          key,
          existing
        );

      }
      else {

        const legal =
          calculateLegalReferenceScore(
            item,
            legalReferences
          );

        merged.set(
          key,
          {

            ...item,

            keywordScore:
              0,

            vectorScore:
              normalizedVectorScore,

            legalScore:
              Number(
                legal.score || 0
              ),

            matchedLegalReferences:
              legal.matched || [],

            hybridScore:
              (
                Number(
                  legal.score || 0
                ) * 0.50
              ) +

              (
                normalizedVectorScore * 0.65
              )

          }
        );

      }

    }
  );

  // ==========================================
  // RANK
  // ==========================================

  const rankedResults =
    Array.from(
      merged.values()
    ).sort(
      (a, b) => {

        // --------------------------------------
        // Legal reference priority
        // --------------------------------------

        if (
          legalReferences &&
          (
            legalReferences.goNumbers?.length ||
            legalReferences.sections?.length ||
            legalReferences.rules?.length ||
            legalReferences.dates?.length
          )
        ) {

          if (
            a.legalScore !==
            b.legalScore
          ) {

            return (
              b.legalScore -
              a.legalScore
            );

          }

        }

        // --------------------------------------
        // Hybrid score
        // --------------------------------------

        return (
          Number(
            b.hybridScore || 0
          ) -
          Number(
            a.hybridScore || 0
          )
        );

      }
    );

  // ==========================================
  // FINAL RESULTS
  // ==========================================

  const finalResults =
    rankedResults.slice(
      0,
      limit
    );

  console.log(
    `🔀 Hybrid results: ${finalResults.length}`
  );

  finalResults.forEach(
    (item, index) => {

      console.log(

        `🔀 Hybrid ${index + 1}:`,

        item.fileName,

        '| chunk:',
        item.chunkIndex,

        '| keyword:',
        item.keywordScore,

        '| legal:',
        item.legalScore,

        '| vector:',
        item.vectorScore,

        '| hybrid:',
        item.hybridScore,

        '| matched:',
        (
          item.matchedLegalReferences || []
        ).join(', ')

      );

    }
  );

  return finalResults;
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

/**
 * OCR a PDF when normal text extraction returns no usable text.
 * Supports Tamil + English.
 */
async function extractTextWithOCR(
  pdfBuffer,
  fileName = 'document.pdf'
) {

  console.log(
    `🔍 Starting OCR: ${fileName}`
  );

  if (
    !pdfBuffer ||
    !Buffer.isBuffer(pdfBuffer)
  ) {
    throw new Error(
      'Invalid PDF buffer for OCR.'
    );
  }

  let worker = null;
  let pdf = null;

  try {

    // ==========================================
    // LOAD PDF
    // ==========================================

    const pdfData =
      new Uint8Array(pdfBuffer);

    pdf =
      await pdfjsLib.getDocument({
        data: pdfData
      }).promise;

    console.log(
      `📄 OCR PDF pages: ${pdf.numPages}`
    );


    // ==========================================
    // CREATE TESSERACT WORKER
    // ==========================================

    worker =
      await createWorker(
        'tam+eng'
      );

    let fullText = '';


    // ==========================================
    // PROCESS PAGE BY PAGE
    // ==========================================

    for (
      let pageNumber = 1;
      pageNumber <= pdf.numPages;
      pageNumber++
    ) {

      console.log(
        `🔎 OCR page ${pageNumber}/${pdf.numPages}: ${fileName}`
      );

      let page = null;
      let canvas = null;
      let renderTask = null;

      try {

        // ========================================
        // GET PAGE
        // ========================================

        page =
          await pdf.getPage(
            pageNumber
          );


        // ========================================
        // OCR RESOLUTION
        // ========================================

        const scale = 1.5;

        const viewport =
          page.getViewport({
            scale
          });


        // ========================================
        // CREATE CANVAS
        // ========================================

        canvas =
          createCanvas(
            Math.ceil(
              viewport.width
            ),
            Math.ceil(
              viewport.height
            )
          );

        const context =
          canvas.getContext('2d');


        // ========================================
        // RENDER PDF PAGE
        // ========================================

        renderTask =
          page.render({
            canvasContext: context,
            viewport
          });


        await renderTask.promise;


        // ========================================
        // IMPORTANT:
        // DO NOT CALL renderTask.cancel()
        // AFTER SUCCESSFUL RENDER
        // ========================================


        // ========================================
        // CONVERT CANVAS TO PNG
        // ========================================

        const imageBuffer =
          canvas.toBuffer(
            'image/png'
          );


        // ========================================
        // OCR
        // ========================================

        const result =
          await worker.recognize(
            imageBuffer
          );

        const pageText =
          result?.data?.text || '';


        console.log(
          `📝 OCR page ${pageNumber}: ${pageText.length} characters`
        );


        if (
          pageText.trim()
        ) {

          fullText +=
            `\n\n===== PAGE ${pageNumber} =====\n\n` +
            pageText.trim();
        }


        // ========================================
        // CLEANUP
        // ========================================

        /*
         * IMPORTANT:
         *
         * DO NOT call:
         *
         * renderTask.cancel()
         *
         * here.
         *
         * The render has already completed.
         */


        if (page) {

          try {

            page.cleanup();

          } catch (cleanupError) {

            console.log(
              `⚠️ Page cleanup warning ${pageNumber}:`,
              cleanupError.message
            );

          }

        }


        // Release references

        renderTask = null;
        page = null;
        canvas = null;


      } catch (pageError) {

        console.error(
          `⚠️ OCR page ${pageNumber} failed:`,
          pageError.message
        );


        // ========================================
        // FAILED PAGE CLEANUP
        // ========================================

        /*
         * DO NOT call renderTask.cancel()
         * because that itself can trigger the
         * CanvasElement error.
         */

        if (page) {

          try {

            page.cleanup();

          } catch (_) {}

        }


        renderTask = null;
        page = null;
        canvas = null;


        /*
         * Continue with next page
         */

        continue;
      }


      // ========================================
      // SMALL DELAY
      // ========================================

      await new Promise(
        resolve =>
          setTimeout(
            resolve,
            100
          )
      );

    }


    // ==========================================
    // CLEAN PDF
    // ==========================================

    if (pdf) {

      try {

        await pdf.cleanup();

      } catch (cleanupError) {

        console.log(
          '⚠️ PDF cleanup warning:',
          cleanupError.message
        );

      }

    }


    pdf = null;


    // ==========================================
    // TERMINATE TESSERACT
    // ==========================================

    if (worker) {

      try {

        await worker.terminate();

      } catch (workerError) {

        console.log(
          '⚠️ Tesseract cleanup warning:',
          workerError.message
        );

      }

      worker = null;

    }


    // ==========================================
    // CLEAN OCR TEXT
    // ==========================================

    const cleanedText =
      fullText
        .replace(/\r/g, '')
        .replace(/[ \t]+/g, ' ')
        .replace(/\n{3,}/g, '\n\n')
        .trim();


    // ==========================================
    // CHECK RESULT
    // ==========================================

    if (!cleanedText) {

      console.log(
        `⚠️ OCR also found no text: ${fileName}`
      );

      return '';

    }


    console.log(
      `✅ OCR completed: ${fileName} | ${cleanedText.length} characters`
    );


    return cleanedText;


  } catch (error) {

    console.error(
      `❌ OCR failed: ${fileName}`,
      error
    );


    // ==========================================
    // SAFE PDF CLEANUP
    // ==========================================

    if (pdf) {

      try {

        await pdf.cleanup();

      } catch (_) {}

      pdf = null;

    }


    // ==========================================
    // SAFE TESSERACT CLEANUP
    // ==========================================

    if (worker) {

      try {

        await worker.terminate();

      } catch (_) {}

      worker = null;

    }


    throw error;

  }

}


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
     * OPTIONAL CATEGORY SCOPE
     * (sent by the frontend when a category tab is open)
     */

    const requestedCategory =
      typeof req.body?.category === 'string'
        ? req.body.category.trim()
        : null;

    const requestedFileIds =
      Array.isArray(req.body?.fileIds)
        ? req.body.fileIds.filter(id => typeof id === 'string' && id)
        : [];


    /*
     * CONVERSATION HISTORY (for follow-up questions)
     * Frontend sends the running `aiChatHistory` array so a
     * question like "அதற்கான படிவம் என்ன?" can be understood in
     * the context of what was just discussed. Only the last few
     * turns are kept — enough for context, small enough to not
     * blow up the Gemini prompt or dilute the search query.
     */

    const aiChatHistory =
      Array.isArray(req.body?.aiChatHistory)
        ? req.body.aiChatHistory
            .filter(
              item =>
                item &&
                typeof item === 'object'
            )
            .map(item => ({
              question:
                String(
                  item.question ?? item.q ?? ''
                ).trim(),
              answer:
                String(
                  item.answer ?? item.a ?? ''
                ).trim()
            }))
            .filter(item => item.question)
            .slice(-4)
        : [];

    /*
     * SEARCH QUERY
     * Widen retrieval for follow-ups by folding the recent
     * question(s) into the search text — a short follow-up alone
     * ("அது எந்த ஆண்டு?") often has no keyword overlap with the
     * right document on its own.
     */

    const searchQuery =
      aiChatHistory.length
        ? `${aiChatHistory.map(h => h.question).join(' ')} ${cleanQuestion}`
            .trim()
            .replace(/\s+/g, ' ')
        : cleanQuestion;

    /*
     * CONVERSATION HISTORY BLOCK
     * (fed to Gemini so it can resolve pronouns/references from
     *  the current question back to the earlier Q&A)
     */

    const conversationHistoryBlock =
      aiChatHistory.length
        ? aiChatHistory
            .map(
              (h, i) =>
                `Q${i + 1}: ${h.question}\nA${i + 1}: ${h.answer || '(no answer recorded)'}`
            )
            .join('\n\n')
        : '';


    /*
     * NORMALIZED SEARCH KEY
     * (scope the dedupe key by category too, so the same
     *  question in two different categories isn't treated
     *  as a duplicate of each other)
     */

    const searchKey =
      `${requestedCategory || 'all'}::${cleanQuestion.toLowerCase()}`;


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
       * HYBRID (KEYWORD + VECTOR) SEARCH
       * Scoped to the requested category's file IDs when the
       * frontend has one open; otherwise searches everything.
       */

      const hybridChunks =
        await searchHybridChunks(
          searchQuery,
          5,
          requestedFileIds
        );


      /*
       * CONFIDENCE FILTER
       * $vectorSearch always returns its nearest neighbours,
       * even when none of them actually match the question.
       * Drop chunks with no keyword/legal-reference overlap AND
       * a weak vector score, so a barely-related PDF doesn't get
       * shown as "the" source for an unrelated question. Only
       * applied when we have at least one solid match — if every
       * result is weak, keep them all so we can still fall back
       * to "no answer found" using the same data as before.
       */

      const MIN_VECTOR_SCORE = 0.72;

      const hasStrongMatch =
        hybridChunks.some(
          item =>
            Number(item.keywordScore || 0) > 0 ||
            Number(item.legalScore || 0) > 0 ||
            Number(item.vectorScore || 0) >= MIN_VECTOR_SCORE
        );

      const relevantChunks =
        hasStrongMatch
          ? hybridChunks.filter(
              item =>
                Number(item.keywordScore || 0) > 0 ||
                Number(item.legalScore || 0) > 0 ||
                Number(item.vectorScore || 0) >= MIN_VECTOR_SCORE
            )
          : hybridChunks;


      console.log(
        `📚 Retrieved ${relevantChunks.length} relevant chunks` +
        (requestedCategory ? ` (category: ${requestedCategory})` : '')
      );


      /*
       * CATALOGUE FALLBACK
       * Title-only search over the frontend's pages{} list
       * (Revenue_Subjects.html). Catches documents that exist
       * on the portal but haven't been chunked/embedded yet.
       */

      const catalogueMatches =
        searchPageCatalogue(
          searchQuery,
          3,
          requestedFileIds
        );

      console.log(
        `🗂️ Catalogue title matches: ${catalogueMatches.length}`
      );


      /*
       * NO RESULTS
       */

      if (
        !relevantChunks ||
        !relevantChunks.length
      ) {

        if (catalogueMatches.length) {

          return res.json({

            success: true,

            question:
              cleanQuestion,

            answer:
              'இந்தக் கேள்வி தொடர்பாக கிடைக்கப்பெற்ற ஆவணங்களின் முழு உள்ளடக்கத்தில் ' +
              'AI இன்னும் தேடவில்லை. ஆனால் போர்ட்டலில் பின்வரும் ஆவணங்கள் இதே தலைப்பில் ' +
              'உள்ளன — அவற்றை நேரடியாக பார்வையிடவும்:',

            sources:
              catalogueMatches.map(item => ({
                fileName: item.text,
                driveUrl: item.href,
                indexed: false
              }))

          });

        }

        return res.json({

          success: true,

          question:
            cleanQuestion,

          answer:
            'கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை.',

          sources: []

        });

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
            `| hybridScore:`,
            item.hybridScore
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
${conversationHistoryBlock
  ? `CONVERSATION SO FAR (most recent last)\n=======================================\n\n${conversationHistoryBlock}\n\n`
  : ''}
CURRENT USER QUESTION
======================

${cleanQuestion}

${requestedCategory
  ? `REQUESTED CATEGORY\n===================\n\n${requestedCategory}\n\n`
  : ''}

RETRIEVED REVENUE DEPARTMENT DOCUMENTS
======================================

${context}


TASK
====

Answer the CURRENT USER QUESTION using the retrieved document content above.

IMPORTANT:

- Examine ALL retrieved document contents.
- If the answer is present in ANY retrieved document, answer it.
- Do NOT require exact wording.
- Summarize and explain the retrieved content when appropriate.
- Do NOT use outside knowledge.
- Do NOT invent missing information.
- Mention the relevant document name when useful.
- If CURRENT USER QUESTION is a follow-up (e.g. it uses "அது",
  "அதற்கு", "இது", "that", "it", or otherwise only makes sense
  together with the CONVERSATION SO FAR), use that conversation
  to understand what is being asked, but still answer strictly
  from the RETRIEVED REVENUE DEPARTMENT DOCUMENTS above — do not
  pull facts only from the earlier conversation turns.
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
                item.score,

              indexed: true

            }
          );

        }

      }


      /*
       * ADD CATALOGUE-ONLY MATCHES
       * (documents whose title matches but that weren't
       *  already surfaced via chunk/vector search)
       */

      for (
        const item of catalogueMatches
      ) {

        const key =
          item.driveFileId || item.href;

        if (!uniqueSources.has(key)) {

          uniqueSources.set(
            key,
            {
              fileName: item.text,
              driveUrl: item.href,
              indexed: false
            }
          );

        }

      }


      /*
       * CAP FINAL SOURCE LIST
       * relevantChunks (already ranked by hybridScore) were added
       * to uniqueSources first, so slicing keeps the strongest,
       * genuinely-retrieved PDFs and only lets a couple of
       * catalogue-title fallbacks through after them.
       */

      const MAX_SOURCES = 5;

      const sources =
        Array.from(
          uniqueSources.values()
        ).slice(0, MAX_SOURCES);


      /*
       * APPEND SOURCE LINE TO ANSWER TEXT
       * In addition to the separate `sources` array (used by the
       * UI's source cards), the user asked for the top matching
       * PDF + link to also appear as the last line of the answer
       * text itself, e.g.:
       *   Source : FORM 5.pdf
       *   https://drive.google.com/file/d/xxxx/view
       */

      const topSource =
        sources.length ? sources[0] : null;

      const answerWithSource =
        answer && topSource && topSource.fileName
          ? `${answer}\n\nSource : ${topSource.fileName}` +
            (
              topSource.driveUrl
                ? `\n${topSource.driveUrl}`
                : ''
            )
          : answer;


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

        answer:
          answerWithSource,

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
   TEST KEYWORD SEARCH (debug endpoint)
========================================================= */

app.post(
  '/keyword-search',
  asyncHandler(
    async (req, res) => {

      const question =
        String(req.body?.question || '').trim();

      if (!question) {

        return res.status(400).json({
          success: false,
          error: 'Question is required.'
        });

      }

      const fileIds =
        Array.isArray(req.body?.fileIds)
          ? req.body.fileIds.filter(id => typeof id === 'string' && id)
          : [];

      const results =
        await searchKeywordChunks(
          question,
          10,
          fileIds
        );

      return res.json({
        success: true,
        question,
        count: results.length,
        results
      });

    }
  )
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
