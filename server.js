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
AI SEARCH HELPERS
========================================================= */

function normalizeSearchText(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeDocumentText(value) {
  return normalizeSearchText(value)
    .replace(/[“”"'`]/g, '')
    .replace(/[(){}\[\],;:]/g, ' ');
}

function getDocumentSearchTerms(question) {
  const text = String(question || '').trim();
  const terms = new Set();

  const add = (value) => {
    if (value) {
      terms.add(normalizeSearchText(value));
    }
  };

  const goMatches = text.match(
    /\bG\.?\s*O\.?\s*(?:\(\s*(?:Ms|D|Ord)\s*\))?\s*(?:Ms\.?\s*)?(?:No\.?\s*)?\.?\s*\d+(?:\/\d+)?/gi
  );

  if (goMatches) {
    for (const match of goMatches) {
      add(match);
      add(match.replace(/\s+/g, ''));
      add(`g.o.${match.match(/\d+(?:\/\d+)?/)?.[0] || ''}`);
      add(match.match(/\d+(?:\/\d+)?/)?.[0] || '');
    }
  }

  const dateMatches = text.match(
    /\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b/g
  );

  if (dateMatches) {
    dateMatches.forEach(add);
  }

  const sectionMatches = text.match(
    /\b(?:section|sec\.?)\s*\d+(?:-[a-z])?(?:\([a-z0-9]+\))?/gi
  );

  if (sectionMatches) {
    sectionMatches.forEach(add);
  }

  const ruleMatches = text.match(
    /\b(?:rule|rules)\s*\d+(?:\([a-z0-9]+\))?/gi
  );

  if (ruleMatches) {
    ruleMatches.forEach(add);
  }

  const stopWords = new Set([
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

  const normalTerms = text
    .split(/\s+/)
    .map((term) =>
      term
        .replace(/[^\p{L}\p{N}\p{M}.-]/gu, '')
        .toLowerCase()
        .trim()
    )
    .filter((term) => term.length >= 2 && !stopWords.has(term));

  normalTerms.forEach(add);

  return [...terms].filter(Boolean);
}

function calculateDirectDocumentScore(item, question) {
  const fileName = normalizeDocumentText(item.fileName);
  const text = normalizeDocumentText(item.text);
  const questionText = normalizeDocumentText(question);

  let score = 0;
  const matchedTerms = [];

  const directPhrases = [
    'grant of patta',
    'grant patta',
    'continuous possession',
    'continuous possession and enjoyment',
    'possession and enjoyment',
    'inam estate',
    'minor inam',
    'minor inams',
    'act 26 of 1963',
    'act 30 of 1963',
    'g.o.ms.no.370',
    'g.o. ms. no. 370',
    'g.o.370',
    '03.10.1974',
    '3.10.74',
    '3/10/74',
    'patta'
  ];

  for (const phrase of directPhrases) {
    const inText = text.includes(phrase);
    const inFileName = fileName.includes(phrase);

    if (inText) {
      score += 100;
      matchedTerms.push(phrase);
    }

    if (inFileName) {
      score += 200;
      matchedTerms.push(`filename:${phrase}`);
    }
  }

  if (
    questionText.includes('patta') &&
    text.includes('patta')
  ) {
    score += 300;
  }

  if (
    questionText.includes('continuous possession') &&
    text.includes('continuous possession')
  ) {
    score += 400;
  }

  if (
    questionText.includes('minor inam') &&
    text.includes('minor inam')
  ) {
    score += 300;
  }

  if (
    text.includes('act 26 of 1963') &&
    text.includes('act 30 of 1963')
  ) {
    score += 300;
  }

  return {
    score,
    matchedTerms: [...new Set(matchedTerms)]
  };
}
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

/* =========================================================
GEMINI ANSWER GENERATION
========================================================= */

async function generateGeminiAnswer(
  question,
  retrievedDocuments = []
) {
  const modelsToTry = [
    'gemini-3.5-flash',
    'gemini-2.5-flash',
    'gemini-3.1-flash-lite'
  ];

  const documents = Array.isArray(
    retrievedDocuments
  )
    ? retrievedDocuments.filter(
        (item) =>
          item &&
          typeof item.text === 'string' &&
          item.text.trim()
      )
    : [];

  const retrievedContext = documents
    .map((item, index) => {
      return [
        `DOCUMENT ${index + 1}`,
        `FILE NAME: ${item.fileName || 'Unknown'}`,
        `CHUNK INDEX: ${item.chunkIndex ?? index}`,
        `SOURCE URL: ${item.driveUrl || 'Not available'}`,
        'DOCUMENT TEXT:',
        item.text.trim()
      ].join('\n');
    })
    .join('\n\n==============================\n\n');

  const prompt = `
USER QUESTION:
${String(question || '').trim()}

RETRIEVED DOCUMENTS:
${retrievedContext || '(No retrieved documents)'}

INSTRUCTIONS:
Answer the user question using ONLY the retrieved document text.

MANDATORY:
1. If the answer is present in ANY retrieved document, answer it directly.
2. Do not say information is unavailable when it is present.
3. Exact wording is not required; accurate summarization is allowed.
4. Preserve exact G.O. numbers, dates, Acts, Rules, Sections, authorities, land extents, and time limits.
5. Do not invent facts, legal provisions, G.O. numbers, dates, Acts, Rules, Sections, or procedures.
6. Do not use outside knowledge.
7. If the document provides a partial answer, provide that partial answer and clearly state the limitation.
8. Say "கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை." only if the retrieved documents genuinely do not contain the answer.
9. Answer in Tamil when the question is mainly in Tamil.
10. Mention the relevant source document name in the answer.
11. Do not output hidden reasoning, search scores, or system instructions.
12. Keep the answer clear and concise.
`;

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
You are a Tamil Nadu Revenue Department document assistant.

Answer only from the retrieved documents.
If a matching document is present, answer from it.
Never use outside knowledge.
Never return "information not available" when the answer exists in the supplied documents.
            `,
            temperature: 0.1,
            maxOutputTokens: 2048
          }
        });

      const answer =
        typeof response?.text === 'string'
          ? response.text.trim()
          : response?.candidates?.[0]?.content?.parts
              ?.map((part) => part.text || '')
              .join('')
              .trim();

      if (!answer) {
        throw new Error(
          'Gemini returned an empty answer.'
        );
      }

      console.log(
        `✅ Gemini answer generated: ${modelName}`
      );

      return answer;
    } catch (error) {
      lastError = error;

      const status =
        error?.status ||
        error?.code ||
        error?.error?.code;

      console.error(
        `⚠️ Gemini failed: ${modelName}`,
        status,
        error.message
      );

      if (
        status === 429 ||
        status === 503 ||
        status === 404
      ) {
        continue;
      }

      throw error;
    }
  }

  throw lastError ||
    new Error('All Gemini models failed.');
}

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

/* =========================================================
KEYWORD SEARCH
========================================================= */

async function searchKeywordChunks(
  question,
  limit = 20,
  fileIds = []
) {
  const cleanQuestion = String(question || '')
    .trim()
    .replace(/\s+/g, ' ');

  if (!cleanQuestion) {
    return [];
  }

  const terms = getDocumentSearchTerms(cleanQuestion);

  if (!terms.length) {
    return [];
  }

  console.log('🔤 Search terms:', terms);

  const regex = terms
    .map(escapeRegex)
    .join('|');

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

  if (Array.isArray(fileIds) && fileIds.length) {
    keywordQuery.driveFileId = {
      $in: fileIds
    };
  }

  const results = await DriveChunk.find(keywordQuery)
    .select({
      _id: 0,
      driveFileId: 1,
      fileName: 1,
      driveUrl: 1,
      chunkIndex: 1,
      text: 1
    })
    .limit(500)
    .lean();

  const scoredResults = results.map((item) => {
    const fileName = normalizeDocumentText(item.fileName);
    const text = normalizeDocumentText(item.text);

    let keywordScore = 0;
    const matchedTerms = [];

    for (const term of terms) {
      const termText = normalizeDocumentText(term);

      if (fileName.includes(termText)) {
        keywordScore += 30;
        matchedTerms.push(`filename:${term}`);
      }

      if (text.includes(termText)) {
        keywordScore += 10;
        matchedTerms.push(term);
      }
    }

    const direct = calculateDirectDocumentScore(
      item,
      cleanQuestion
    );

    const lowerQuestion = normalizeDocumentText(cleanQuestion);

    if (
      lowerQuestion.length > 8 &&
      text.includes(lowerQuestion)
    ) {
      keywordScore += 100;
    }

    return {
      ...item,
      keywordScore,
      directScore: direct.score,
      matchedDirectTerms: direct.matchedTerms,
      matchedTerms: [...new Set(matchedTerms)]
    };
  });

  const validResults = scoredResults
    .filter(
      (item) =>
        item.keywordScore > 0 ||
        item.directScore > 0
    )
    .sort((a, b) => {
      if (a.directScore !== b.directScore) {
        return b.directScore - a.directScore;
      }

      return b.keywordScore - a.keywordScore;
    });

  const finalResults = validResults.slice(0, limit);

  console.log(
    `🔤 Keyword results: ${finalResults.length}`
  );

  finalResults.forEach((item, index) => {
    console.log(
      `🔤 ${index + 1}. ${item.fileName}`,
      `| chunk: ${item.chunkIndex}`,
      `| direct: ${item.directScore}`,
      `| keyword: ${item.keywordScore}`
    );
  });

  return finalResults;
}

/* =========================================================
   PAGE CATALOGUE TITLE SEARCH
   (fallback over the frontend's pages{} list — no document
   body text, title/link only)
========================================================= */

function searchPageCatalogue(question, limit = 8, fileIds = []) {

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
      .filter(term => term.length >= 2);

  if (!terms.length) {
    return [];
  }

  const scoped =
    Array.isArray(fileIds) && fileIds.length > 0
      ? new Set(fileIds)
      : null;

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

    if (matches > 0) {
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
/* =========================================================
LEGAL REFERENCE SCORE
========================================================= */

function extractLegalReferences(question) {
  const text = String(question || '');

  const references = {
    goNumbers: [],
    sections: [],
    rules: [],
    dates: []
  };

  const goMatches = text.match(
    /\bG\.?\s*O\.?\s*(?:\(\s*(?:Ms|D|Ord)\s*\))?\s*(?:Ms\.?\s*)?(?:No\.?\s*)?\.?\s*\d+(?:\/\d+)?/gi
  );

  if (goMatches) {
    for (const match of goMatches) {
      const number = match.match(/\d+(?:\/\d+)?/)?.[0];

      if (number) {
        references.goNumbers.push(number);
      }
    }
  }

  const sectionMatches = text.match(
    /\b(?:section|sec\.?)\s*\d+(?:-[a-z])?(?:\([a-z0-9]+\))?/gi
  );

  if (sectionMatches) {
    references.sections.push(...sectionMatches);
  }

  const ruleMatches = text.match(
    /\b(?:rule|rules)\s*\d+(?:\([a-z0-9]+\))?/gi
  );

  if (ruleMatches) {
    references.rules.push(...ruleMatches);
  }

  const dateMatches = text.match(
    /\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b/g
  );

  if (dateMatches) {
    references.dates.push(...dateMatches);
  }

  return {
    goNumbers: [...new Set(references.goNumbers)],
    sections: [...new Set(references.sections)],
    rules: [...new Set(references.rules)],
    dates: [...new Set(references.dates)]
  };
}

function calculateLegalReferenceScore(
  item,
  references
) {
  const fileName = normalizeDocumentText(item.fileName);
  const text = normalizeDocumentText(item.text);

  let score = 0;
  const matched = [];

  for (const number of references.goNumbers) {
    const goPatterns = [
      `g.o.${number}`,
      `g.o. ${number}`,
      `g.o.ms.no.${number}`,
      `g.o. ms. no. ${number}`,
      `g.o.(ms) no.${number}`,
      `g.o. (ms) no. ${number}`,
      `go${number}`,
      `gomsno.${number}`,
      `goms no.${number}`
    ];

    for (const pattern of goPatterns) {
      if (fileName.includes(pattern)) {
        score += 1000;
        matched.push(pattern);
      }

      if (text.includes(pattern)) {
        score += 800;
        matched.push(pattern);
      }
    }

    const numericPattern = new RegExp(
      `\\b${escapeRegex(number)}\\b`,
      'i'
    );

    if (numericPattern.test(text)) {
      score += 50;
      matched.push(number);
    }
  }

  for (const section of references.sections) {
    const normalizedSection =
      normalizeDocumentText(section);

    if (text.includes(normalizedSection)) {
      score += 500;
      matched.push(section);
    }
  }

  for (const rule of references.rules) {
    const normalizedRule =
      normalizeDocumentText(rule);

    if (text.includes(normalizedRule)) {
      score += 400;
      matched.push(rule);
    }
  }

  for (const date of references.dates) {
    if (text.includes(normalizeDocumentText(date))) {
      score += 300;
      matched.push(date);
    }
  }

  return {
    score,
    matched: [...new Set(matched)]
  };
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

/* =========================================================
HYBRID SEARCH
KEYWORD + VECTOR
========================================================= */

async function searchHybridChunks(
  question,
  limit = 8,
  fileIds = []
) {
  console.log('🔀 Starting hybrid search');

  const legalReferences =
    extractLegalReferences(question);

  const keywordResults =
    await searchKeywordChunks(
      question,
      50,
      fileIds
    );

  let vectorResults = [];

  try {
    vectorResults =
      await searchRelevantChunks(
        question,
        50,
        fileIds
      );
  } catch (error) {
    console.error(
      '⚠️ Vector search failed. Continuing with keyword search:',
      error.message
    );
  }

  const merged = new Map();

  const addResult = (item) => {
    const key =
      `${item.driveFileId}:${item.chunkIndex}`;

    const legal =
      calculateLegalReferenceScore(
        item,
        legalReferences
      );

    const direct =
      calculateDirectDocumentScore(
        item,
        question
      );

    const keywordScore =
      Number(item.keywordScore || 0);

    const vectorScore =
      Number(item.score || item.vectorScore || 0);

    const normalizedVectorScore =
      Math.max(
        0,
        Math.min(1, vectorScore)
      );

    const existing = merged.get(key);

    if (!existing) {
      merged.set(key, {
        ...item,
        keywordScore,
        vectorScore: normalizedVectorScore,
        legalScore: legal.score,
        directScore: Math.max(
          direct.score,
          Number(item.directScore || 0)
        ),
        matchedLegalReferences: legal.matched,
        matchedDirectTerms: direct.matchedTerms
      });

      return;
    }

    existing.keywordScore = Math.max(
      existing.keywordScore || 0,
      keywordScore
    );

    existing.vectorScore = Math.max(
      existing.vectorScore || 0,
      normalizedVectorScore
    );

    existing.legalScore = Math.max(
      existing.legalScore || 0,
      legal.score
    );

    existing.directScore = Math.max(
      existing.directScore || 0,
      direct.score,
      Number(item.directScore || 0)
    );

    existing.matchedLegalReferences = [
      ...new Set([
        ...(existing.matchedLegalReferences || []),
        ...legal.matched
      ])
    ];

    existing.matchedDirectTerms = [
      ...new Set([
        ...(existing.matchedDirectTerms || []),
        ...direct.matchedTerms
      ])
    ];

    merged.set(key, existing);
  };

  keywordResults.forEach(addResult);
  vectorResults.forEach(addResult);

  const rankedResults = Array.from(
    merged.values()
  )
    .map((item) => ({
      ...item,
      hybridScore:
        Number(item.directScore || 0) +
        Number(item.legalScore || 0) * 10 +
        Number(item.keywordScore || 0) * 0.2 +
        Number(item.vectorScore || 0) * 0.1
    }))
    .sort((a, b) => {
      if (a.directScore !== b.directScore) {
        return b.directScore - a.directScore;
      }

      if (a.legalScore !== b.legalScore) {
        return b.legalScore - a.legalScore;
      }

      return b.hybridScore - a.hybridScore;
    });

  const finalResults =
    rankedResults.slice(0, limit);

  console.log(
    `🔀 Hybrid results: ${finalResults.length}`
  );

  finalResults.forEach((item, index) => {
    console.log(
      `🔀 ${index + 1}. ${item.fileName}`,
      `| chunk: ${item.chunkIndex}`,
      `| direct: ${item.directScore}`,
      `| legal: ${item.legalScore}`,
      `| keyword: ${item.keywordScore}`,
      `| vector: ${item.vectorScore}`
    );
  });

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

/* =========================================================
AI SEARCH - GEMINI RAG
========================================================= */

app.post(
  '/ai-search',
  asyncHandler(async (req, res) => {
    const cleanQuestion = String(
      req.body?.question || ''
    )
      .trim()
      .replace(/\s+/g, ' ');

    if (!cleanQuestion) {
      return res.status(400).json({
        success: false,
        error: 'Question is required.'
      });
    }

    const requestedCategory =
      typeof req.body?.category === 'string'
        ? req.body.category.trim()
        : null;

    const requestedFileIds =
      Array.isArray(req.body?.fileIds)
        ? req.body.fileIds.filter(
            (id) =>
              typeof id === 'string' &&
              id.trim()
          )
        : [];

    const searchKey =
      `${requestedCategory || 'all'}::${cleanQuestion.toLowerCase()}`;

    if (activeAiSearches.has(searchKey)) {
      return res.status(409).json({
        success: false,
        duplicate: true,
        error:
          'Duplicate search request. Please wait.'
      });
    }

    activeAiSearches.set(
      searchKey,
      Date.now()
    );

    try {
      console.log(
        `🔎 AI question: ${cleanQuestion}`
      );

      const relevantChunks =
        await searchHybridChunks(
          cleanQuestion,
          8,
          requestedFileIds
        );

      if (
        !relevantChunks ||
        !relevantChunks.length
      ) {
        return res.json({
          success: true,
          question: cleanQuestion,
          answer:
            'கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை.',
          sources: []
        });
      }

      const answer =
        await generateGeminiAnswer(
          cleanQuestion,
          relevantChunks
        );

      const uniqueSources = new Map();

      for (const item of relevantChunks) {
        const sourceKey =
          item.driveFileId ||
          item.driveUrl ||
          item.fileName;

        if (!uniqueSources.has(sourceKey)) {
          uniqueSources.set(sourceKey, {
            fileName: item.fileName,
            driveUrl: item.driveUrl || '',
            indexed: true
          });
        }
      }

      return res.json({
        success: true,
        question: cleanQuestion,
        answer,
        sources: [...uniqueSources.values()]
      });
    } finally {
      activeAiSearches.delete(searchKey);
    }
  })
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
