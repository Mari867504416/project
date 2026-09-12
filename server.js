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

  validChunkExists

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
   MONGODB VECTOR SEARCH
========================================================= */

/* =========================================================
   MONGODB VECTOR SEARCH
========================================================= */

async function searchRelevantChunks(
  question,
  limit = 5
) {

  const queryEmbedding =
    await createQueryEmbedding(
      question
    );


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

          _id:
            0,

          fileName:
            1,

          driveUrl:
            1,

          chunkIndex:
            1,

          text:
            1,

          score: {

            $meta:
              'vectorSearchScore'

          }

        }

      }

    ]);


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

  asyncHandler(
    async (req, res) => {

      const {
        question
      } = req.body;


      if (
        !question ||
        !question.trim()
      ) {

        return res.status(400).json({

          error:
            'Question is required.'

        });

      }


      if (
        !process.env.GEMINI_API_KEY
      ) {

        return res.status(500).json({

          error:
            'GEMINI_API_KEY is not configured.'

        });

      }


      try {

        console.log(
          `🔎 Question: ${question}`
        );


        /*
         * STEP 1
         * Vector search
         */

        const relevantChunks =
          await searchRelevantChunks(

            question.trim(),

            5

          );


        console.log(

          `📚 Retrieved ${relevantChunks.length} relevant chunks`

        );


        /*
         * No results
         */

        if (
          !relevantChunks.length
        ) {

          return res.json({

            success:
              true,

            answer:
              'கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை.',

            sources:
              []

          });

        }


        /*
         * STEP 2
         * Build context
         */

        const context =
          relevantChunks

            .map(
              (item, index) => {

                return `

DOCUMENT ${index + 1}

FILE NAME:
${item.fileName}

DOCUMENT CONTENT:
${item.text}

SOURCE:
${item.driveUrl}

`;

              }
            )

            .join(
              '\n-----------------------------\n'
            );


        /*
         * STEP 3
         * Gemini answer
         */

        const response =
          await gemini.models.generateContent({

            model:
              'gemini-3.8-flash',

            contents: `

USER QUESTION:

${question.trim()}


RETRIEVED REVENUE DEPARTMENT DOCUMENTS:

${context}

`,

            config: {

              systemInstruction: `

You are an AI assistant for the Tamil Nadu Revenue Department.

Your task is to answer questions using ONLY the retrieved Revenue Department documents.

STRICT RULES:

1. Do not invent any Government Order.

2. Do not invent any G.O. number.

3. Do not invent dates.

4. Do not invent Acts.

5. Do not invent Rules.

6. Do not invent Sections.

7. Do not invent proceedings.

8. Do not invent circular numbers.

9. Do not assume information that is not present in the retrieved documents.

10. If the answer cannot be established from the retrieved documents, say:

"கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை."

11. If the question is in Tamil, answer in Tamil.

12. If the question is in English, answer in English.

13. When available, mention:

- Exact G.O. number
- Exact date
- Department
- Subject
- Relevant section/rule
- Relevant document name

14. Do not create fake citations.

15. Do not cite documents that were not retrieved.

16. If multiple documents conflict, clearly explain the conflict.

17. Give a concise and official answer.

18. For legal and government questions, distinguish between the document's actual statement and your explanation.

19. Never present assumptions as official Government instructions.

20. If retrieved information is insufficient, clearly say so.

`

            }

          });


        /*
         * STEP 4
         * Sources
         */

        const sources =
          relevantChunks.map(
            item => ({

              fileName:
                item.fileName,

              driveUrl:
                item.driveUrl,

              chunkIndex:
                item.chunkIndex,

              score:
                item.score

            })
          );


        /*
         * STEP 5
         * Response
         */

        res.json({

          success:
            true,

          question:
            question.trim(),

          answer:
            response.text,

          sources

        });


      } catch (error) {

        console.error(
          '❌ Gemini RAG error:',
          error
        );


        res.status(500).json({

          success:
            false,

          error:
            error.message ||
            'Gemini document search failed.'

        });

      }

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
