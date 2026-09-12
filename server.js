require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const OpenAI = require('openai');
const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');
const os = require('os');

const app = express();

/* =========================================================
   OPENAI
========================================================= */
console.log("OPENAI_API_KEY loaded:", !!process.env.OPENAI_API_KEY);
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});


/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '2mb' }));


// General rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Too many requests. Please try again later.'
  }
});

app.use(limiter);


// Stricter limiter for login routes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: {
    error: 'Too many login attempts. Please try again after 15 minutes.'
  }
});


/* =========================================================
   ASYNC ERROR HANDLER
========================================================= */

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);


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

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log('✅ Connected to MongoDB');
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
});


/* =========================================================
   MODELS
========================================================= */


/* ---------------- ADMIN ---------------- */

const adminSchema = new mongoose.Schema({
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
  mongoose.model('Admin', adminSchema);


/* ---------------- OFFICER ---------------- */

const officerSchema = new mongoose.Schema({
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
      validator: v => /^\d{10}$/.test(v),
      message: props =>
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
      validator: v => !v || /^\d{12}$/.test(v),
      message: 'Transaction ID must be exactly 12 digits'
    }
  },

  subscriptionDate: Date,

  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Officer =
  mongoose.models.Officer ||
  mongoose.model('Officer', officerSchema);


/* ---------------- RESULT ---------------- */

const resultSchema = new mongoose.Schema({
  username: String,
  name: String,
  address: String,
  score: Number,
  total: Number,

  date: {
    type: Date,
    default: Date.now
  }
});

const Result =
  mongoose.models.Result ||
  mongoose.model('Result', resultSchema);


/* ---------------- TRANSFER APPLICATION ---------------- */

const transferSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },

  transferType: {
    type: String,
    enum: ['One Way', 'Mutual'],
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
      "SRI",
      "JRI",
      "TYPIST",
      "STENO TYPIST",
      "DEPUTY TAHSILDAR",
      "TAHSILDAR"
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

  option2: String,

  option3: String,

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
   GOOGLE DRIVE → OPENAI SYNC MODEL
========================================================= */

const driveSyncSchema = new mongoose.Schema({

  driveFileId: {
    type: String,
    required: true,
    unique: true
  },

  fileName: {
    type: String,
    required: true
  },

  modifiedTime: String,

  md5Checksum: String,

  openaiFileId: String,

  vectorStoreFileId: String,

  status: {
    type: String,
    enum: [
      'uploaded',
      'updated',
      'failed'
    ],

    default: 'uploaded'
  },

  errorMessage: String,

  lastSyncedAt: {
    type: Date,
    default: Date.now
  }
});

const DriveSync =
  mongoose.models.DriveSync ||
  mongoose.model('DriveSync', driveSyncSchema);


/* =========================================================
   CONSTANTS
========================================================= */

const ALLOWED_DESIGNATIONS = [
  "SRI",
  "JRI",
  "TYPIST",
  "STENO TYPIST",
  "DEPUTY TAHSILDAR",
  "TAHSILDAR"
];


// Admin password reset secret
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
        username: 'admin'
      });

    if (!exists) {

      const hash =
        await bcrypt.hash(
          'admin123',
          10
        );

      await Admin.create({
        username: 'admin',
        password: hash
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
   GOOGLE DRIVE
========================================================= */

function getGoogleDriveClient() {

  if (!process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL) {
    throw new Error(
      'GOOGLE_SERVICE_ACCOUNT_EMAIL is not configured.'
    );
  }

  if (!process.env.GOOGLE_PRIVATE_KEY) {
    throw new Error(
      'GOOGLE_PRIVATE_KEY is not configured.'
    );
  }

  const auth = new google.auth.JWT({

    email:
      process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,

    key:
      process.env.GOOGLE_PRIVATE_KEY
        .replace(/\\n/g, '\n'),

    scopes: [
      'https://www.googleapis.com/auth/drive.readonly'
    ]

  });

  return google.drive({
    version: 'v3',
    auth
  });
}


/* =========================================================
   GET CHILDREN OF GOOGLE DRIVE FOLDER
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

        fields: 'nextPageToken,files(id,name,mimeType,size,modifiedTime,md5Checksum)',

        pageSize: 100,

        pageToken,

        supportsAllDrives: true,

        includeItemsFromAllDrives: true

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

  const foldersToProcess = [
    rootFolderId
  ];

  const visitedFolders =
    new Set();


  while (foldersToProcess.length > 0) {

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


    for (const file of children) {

      // PDF
      if (
        file.mimeType ===
        'application/pdf'
      ) {

        pdfFiles.push(file);

      }

      // Folder
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


  // Make filename safe
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
        alt: 'media',
        acknowledgeAbuse: true
      },

      {
        responseType: 'stream'
      }

    );


  return new Promise(
    (resolve, reject) => {

      const dest =
        fs.createWriteStream(
          tempPath
        );


      response.data
        .on('error', reject)
        .pipe(dest);


      dest.on(
        'finish',
        () => resolve(tempPath)
      );


      dest.on(
        'error',
        reject
      );

    }
  );
}


/* =========================================================
   UPLOAD PDF TO OPENAI VECTOR STORE
========================================================= */

async function uploadFileToVectorStore(
  filePath,
  fileName
) {

  const vectorStoreId =
    process.env.OPENAI_VECTOR_STORE_ID;


  if (!vectorStoreId) {

    throw new Error(
      'OPENAI_VECTOR_STORE_ID is not configured.'
    );

  }


  console.log(
    `📤 Uploading to OpenAI: ${fileName}`
  );


  const uploadedFile =
    await openai.files.create({

      file:
        fs.createReadStream(
          filePath
        ),

      purpose: 'assistants'

    });


  console.log(
    `✅ OpenAI File ID: ${uploadedFile.id}`
  );


  const vectorFile =
    await openai.vectorStores.files.create(

      vectorStoreId,

      {
        file_id:
          uploadedFile.id
      }

    );


  console.log(
    `📚 Vector Store File ID: ${vectorFile.id}`
  );


  return {

    fileId:
      uploadedFile.id,

    vectorFileId:
      vectorFile.id

  };

}


/* =========================================================
   GOOGLE DRIVE → VECTOR STORE SYNC
========================================================= */

async function syncGoogleDriveToVectorStore() {

  console.log(
    '🔄 Starting Google Drive → OpenAI sync...'
  );


  const files =
    await getDrivePdfFiles();


  console.log(
    `📂 Found ${files.length} PDF file(s).`
  );


  let uploaded = 0;

  let updated = 0;

  let skipped = 0;

  let failed = 0;


  const details = [];


  for (const file of files) {

    let tempPath = null;


    try {

      console.log(
        `📄 Checking: ${file.name}`
      );


      /*
       * Check whether this Drive file
       * was already synchronized.
       */

      const existing =
        await DriveSync.findOne({
          driveFileId: file.id
        });


      /*
       * If file exists and has not changed,
       * skip upload.
       */

      if (
        existing &&
        existing.modifiedTime ===
          file.modifiedTime &&
        existing.md5Checksum ===
          file.md5Checksum
      ) {

        skipped++;

        details.push({
          file: file.name,
          status: 'skipped'
        });

        continue;

      }


      /*
       * Download PDF
       */

      tempPath =
        await downloadDriveFile(
          file.id,
          file.name
        );


      /*
       * Upload to OpenAI
       */

      const result =
        await uploadFileToVectorStore(
          tempPath,
          file.name
        );


      /*
       * Save synchronization information
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

          openaiFileId:
            result.fileId,

          vectorStoreFileId:
            result.vectorFileId,

          status:
            existing
              ? 'updated'
              : 'uploaded',

          errorMessage:
            null,

          lastSyncedAt:
            new Date()

        },

        {
          upsert: true,
          new: true
        }

      );


      if (existing) {

        updated++;

        details.push({
          file: file.name,
          status: 'updated'
        });

      } else {

        uploaded++;

        details.push({
          file: file.name,
          status: 'uploaded'
        });

      }


    } catch (error) {

      failed++;


      console.error(
        `❌ Failed: ${file.name}`,
        error.message
      );


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

          errorMessage:
            error.message,

          lastSyncedAt:
            new Date()

        },

        {
          upsert: true
        }

      );


      details.push({
        file: file.name,
        status: 'failed',
        error: error.message
      });


    } finally {

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
            'Temporary file cleanup error:',
            cleanupError.message
          );

        }

      }

    }

  }


  console.log(
    '======================================'
  );

  console.log(
    'Google Drive sync completed'
  );

  console.log(
    `Total   : ${files.length}`
  );

  console.log(
    `Uploaded: ${uploaded}`
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

    uploaded,

    updated,

    skipped,

    failed,

    details

  };

}


/* =========================================================
   ROUTES
========================================================= */


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  '/',
  (req, res) => {

    res.json({
      status:
        'TN Govt Servant Portal API running ✅'
    });

  }
);


/* =========================================================
   AUTH ROUTES
========================================================= */


/* ---------- ADMIN LOGIN ---------- */

app.post(
  '/admin/login',
  loginLimiter,
  asyncHandler(async (req, res) => {

    const {
      username,
      password
    } = req.body;


    if (!username || !password) {

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

  })
);


/* ---------- ADMIN RESET PASSWORD ---------- */

app.post(
  '/admin/reset-password',
  asyncHandler(async (req, res) => {

    const {
      secretCode,
      password
    } = req.body;


    if (!secretCode || !password) {

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


    if (password.length < 8) {

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
        username: 'admin'
      },

      {
        password: hash
      }

    );


    res.json({
      message:
        'Admin password reset successfully.'
    });

  })
);


/* ---------- OFFICER LOGIN ---------- */

app.post(
  '/login',
  loginLimiter,
  asyncHandler(async (req, res) => {

    const {
      username,
      password
    } = req.body;


    if (!username || !password) {

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

  })
);


/* ---------- OFFICER SIGNUP ---------- */

app.post(
  '/signup',
  asyncHandler(async (req, res) => {

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


    if (!isValidMobile(mobile)) {

      return res.status(400).json({
        error:
          'Mobile must be exactly 10 digits.'
      });

    }


    if (!isValidUsername(username)) {

      return res.status(400).json({
        error:
          'Username: 4-20 chars, letters/numbers/underscore only.'
      });

    }


    if (password.length < 8) {

      return res.status(400).json({
        error:
          'Password must be at least 8 characters.'
      });

    }


    const existingUser =
      await Officer.findOne({

        $or: [
          { username },
          { mobile }
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
        password: hash

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

  })
);


/* ---------- OFFICER RESET PASSWORD ---------- */

app.post(
  '/officer/reset-password',
  asyncHandler(async (req, res) => {

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


    if (!isValidMobile(mobile)) {

      return res.status(400).json({
        error:
          'Invalid mobile number.'
      });

    }


    if (password.length < 8) {

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

  })
);


/* =========================================================
   SUBSCRIPTION ROUTES
========================================================= */


/* ---------- SUBMIT TRANSACTION ---------- */

app.post(
  '/submit-transaction',
  asyncHandler(async (req, res) => {

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
      existing.username !== username
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
          subscribed: false
        },

        {
          new: true
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

  })
);


/* ---------- OFFICER STATUS ---------- */

app.post(
  '/officer/status',
  asyncHandler(async (req, res) => {

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

  })
);


/* =========================================================
   ADMIN ROUTES
========================================================= */


/* ---------- GET ALL OFFICERS ---------- */

app.get(
  '/admin/officers',
  asyncHandler(async (req, res) => {

    const officers =
      await Officer.find(
        {},
        {
          password: 0
        }
      ).sort({
        createdAt: -1
      });


    res.json(
      officers
    );

  })
);


/* ---------- ACTIVATE SUBSCRIPTION ---------- */

app.post(
  '/admin/activate',
  asyncHandler(async (req, res) => {

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


    if (officer.subscribed) {

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

  })
);


/* ---------- EDIT OFFICER ---------- */

app.post(
  '/admin/officer/update',
  asyncHandler(async (req, res) => {

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


    if (!isValidMobile(mobile)) {

      return res.status(400).json({
        error:
          'Mobile must be exactly 10 digits.'
      });

    }


    const conflict =
      await Officer.findOne({

        mobile,

        username: {
          $ne: username
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
          new: true,
          runValidators: true
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

  })
);


/* ---------- DELETE OFFICER ---------- */

app.post(
  '/admin/officer/delete',
  asyncHandler(async (req, res) => {

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

  })
);


/* =========================================================
   RESULT ROUTES
========================================================= */


/* ---------- SUBMIT RESULT ---------- */

app.post(
  '/submit-result',
  asyncHandler(async (req, res) => {

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

  })
);


/* ---------- GET RESULTS ---------- */

app.get(
  '/get-results',
  asyncHandler(async (req, res) => {

    const list =
      await Result.find()
        .sort({
          date: -1
        });


    res.json(
      list
    );

  })
);


/* =========================================================
   TRANSFER ROUTES
========================================================= */


/* ---------- APPLY TRANSFER ---------- */

app.post(
  '/transfer/apply',
  asyncHandler(async (req, res) => {

    const designation =
      req.body.designation
        ?.trim()
        .toUpperCase();


    if (
      !ALLOWED_DESIGNATIONS
        .includes(
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

  })
);


/* ---------- TRANSFER LIST HELPER ---------- */

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
              createdAt: -1
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
   GOOGLE DRIVE ADMIN SYNC
========================================================= */

app.post(
  '/admin/sync-drive',

  asyncHandler(
    async (req, res) => {

      /*
       * Protect the synchronization endpoint.
       */

      const suppliedSecret =
        req.headers[
          'x-sync-secret'
        ];


      if (
        !process.env.DRIVE_SYNC_SECRET
      ) {

        return res.status(500).json({

          error:
            'DRIVE_SYNC_SECRET is not configured on the server.'

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
        await syncGoogleDriveToVectorStore();


      res.json({

        success:
          true,

        message:
          'Google Drive sync completed.',

        result

      });

    }
  )
);


/* =========================================================
   GOOGLE DRIVE SYNC STATUS
========================================================= */

app.get(
  '/admin/sync-status',
  asyncHandler(async (req, res) => {

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


    const uploaded =
      await DriveSync.countDocuments({
        status: 'uploaded'
      });


    const updated =
      await DriveSync.countDocuments({
        status: 'updated'
      });


    const failed =
      await DriveSync.countDocuments({
        status: 'failed'
      });


    const recent =
      await DriveSync
        .find()
        .sort({
          lastSyncedAt: -1
        })
        .limit(20)
        .select(
          '-__v'
        );


    res.json({

      success:
        true,

      total,

      uploaded,

      updated,

      failed,

      recent

    });

  })
);


/* =========================================================
   AI SEARCH
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
        !process.env.OPENAI_API_KEY
      ) {

        return res.status(500).json({

          error:
            'OPENAI_API_KEY is not configured.'

        });

      }


      if (
        !process.env.OPENAI_VECTOR_STORE_ID
      ) {

        return res.status(500).json({

          error:
            'OPENAI_VECTOR_STORE_ID is not configured.'

        });

      }


      const response =
        await openai.responses.create({

          model:
            'gpt-5.6-luna',


          instructions: `

You are an AI assistant for the
Tamil Nadu Revenue Department.

Your task is to answer questions
using ONLY information contained
in the documents available through
the File Search tool.

The documents may contain:

Government Orders (G.O.s)
Acts
Rules
Revenue Standing Orders
Circulars
Proceedings
Pension rules
Establishment rules
Land matters
Explosives matters
Petroleum matters
Government servant rules
Department instructions
Office proceedings
Other official Revenue Department documents.

IMPORTANT RULES:

1. Do NOT invent any Government Order.

2. Do NOT invent dates.

3. Do NOT invent sections.

4. Do NOT invent rules.

5. Do NOT invent proceedings numbers.

6. Do NOT assume a legal position if the
   required document is unavailable.

7. If the answer cannot be established
   from the available documents, say:

"கிடைக்கப்பெற்ற ஆவணங்களில் இந்த தகவல் இல்லை."

8. Answer in the same language as the
   user's question.

9. If the question is in Tamil,
   answer in official/simple Tamil.

10. If the question is in English,
    answer in clear official English.

11. Wherever possible, mention the
    relevant G.O./Act/Rule/document name,
    number and date.

12. Do not cite a document unless the
    document actually supports the answer.

13. If multiple documents are relevant,
    explain the relationship between them.

`,


          input:
            question.trim(),


          tools: [

            {

              type:
                'file_search',

              vector_store_ids: [

                process.env
                  .OPENAI_VECTOR_STORE_ID

              ]

            }

          ]

        });


      res.json({

        success:
          true,

        question:
          question.trim(),

        answer:
          response.output_text

      });

    }
  )
);


/* =========================================================
   GLOBAL ERROR HANDLER
   MUST BE AFTER ALL ROUTES
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(
      '❌ Unhandled error:',
      err
    );


    // Mongoose validation error
    if (
      err.name ===
      'ValidationError'
    ) {

      const messages =
        Object.values(
          err.errors
        )
        .map(
          e => e.message
        )
        .join(', ');


      return res.status(400).json({

        error:
          messages

      });

    }


    // Duplicate key
    if (
      err.code === 11000
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
