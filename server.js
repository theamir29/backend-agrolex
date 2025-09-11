// ========== IMPORTS ==========
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");
const path = require("path");
// const rateLimit = require("express-rate-limit"); // ВРЕМЕННО ОТКЛЮЧЕНО
require("dotenv").config();

// ========== EXPRESS APP SETUP ==========
const app = express();

// ========== MIDDLEWARE ==========
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://agro-lex.uz",
      "https://www.agro-lex.uz",
      "http://localhost:5173",
      "https://agro-english-master-v2.vercel.app",
    ], // Vite default port
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// RATE LIMITING ВРЕМЕННО ОТКЛЮЧЕНО ДЛЯ РАЗРАБОТКИ
// Раскомментируйте для продакшена
/*
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use("/api/", limiter);
*/

// ========== MONGODB SCHEMAS ==========

// Term Schema - БЕЗ difficulty, с theme вместо category
const termSchema = new mongoose.Schema({
  term_kaa: {
    type: String,
    required: true,
    trim: true,
    index: true,
  },
  term_en: {
    type: String,
    required: true,
    trim: true,
    index: true,
  },
  definition_en: {
    type: String,
    required: true,
  },
  definition_kaa: {
    type: String,
    default: "",
  },
  theme: {
    type: String,
    required: true,
    index: true,
  },
  audio_url: {
    type: String,
    default: "",
  },
  views: {
    type: Number,
    default: 0,
  },
  favorites_count: {
    type: Number,
    default: 0,
  },
  created_by: {
    type: String,
    default: "system",
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
  updated_at: {
    type: Date,
    default: Date.now,
  },
});

// Indexes for better search performance
termSchema.index({ term_kaa: "text", term_en: "text", definition_en: "text" });

// Theme Schema (вместо Category)
const themeSchema = new mongoose.Schema({
  name_en: {
    type: String,
    required: true,
    unique: true,
  },
  name_kaa: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    default: "",
  },
  order: {
    type: Number,
    default: 0,
  },
  terms_count: {
    type: Number,
    default: 0,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
});

// Quiz Result Schema - обновлен для theme
const quizResultSchema = new mongoose.Schema({
  session_id: {
    type: String,
    required: true,
    index: true,
  },
  quiz_type: {
    type: String,
    required: true,
  },
  theme: {
    type: String,
    default: "all",
  },
  total_questions: {
    type: Number,
    required: true,
  },
  correct_answers: {
    type: Number,
    required: true,
  },
  incorrect_answers: {
    type: Number,
    required: true,
  },
  percentage: {
    type: Number,
    required: true,
  },
  time_spent: {
    type: Number, // in seconds
    required: true,
  },
  details: [
    {
      question: String,
      user_answer: String,
      correct_answer: String,
      is_correct: Boolean,
    },
  ],
  created_at: {
    type: Date,
    default: Date.now,
  },
});

// Admin Schema
const adminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    default: "admin",
  },
  last_login: {
    type: Date,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
});

// Activity Log Schema
const activitySchema = new mongoose.Schema({
  action: {
    type: String,
    required: true,
  },
  entity_type: {
    type: String, // 'term', 'theme', 'quiz', etc.
    required: true,
  },
  entity_id: String,
  user: String,
  ip_address: String,
  details: Object,
  created_at: {
    type: Date,
    default: Date.now,
  },
});

// ========== MODELS ==========
const Term = mongoose.model("Term", termSchema);
const Theme = mongoose.model("Theme", themeSchema);
const QuizResult = mongoose.model("QuizResult", quizResultSchema);
const Admin = mongoose.model("Admin", adminSchema);
const Activity = mongoose.model("Activity", activitySchema);

// ========== MULTER SETUP FOR FILE UPLOADS ==========
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: process.env.MAX_FILE_SIZE || 10485760 }, // 10MB default
  fileFilter: function (req, file, cb) {
    if (file.mimetype !== "text/csv") {
      return cb(new Error("Only CSV files are allowed"));
    }
    cb(null, true);
  },
});

// ========== MIDDLEWARE FUNCTIONS ==========

// Authenticate admin middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET ||
        "your_super_secret_jwt_key_change_this_in_production"
    );
    const admin = await Admin.findById(decoded.id);

    if (!admin) {
      return res.status(401).json({ error: "Invalid token" });
    }

    req.admin = admin;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Authentication failed" });
  }
};

// Log activity middleware
const logActivity = async (action, entityType, entityId, user, req) => {
  try {
    await Activity.create({
      action,
      entity_type: entityType,
      entity_id: entityId,
      user: user || "anonymous",
      ip_address: req.ip,
      details: req.body,
    });
  } catch (error) {
    console.error("Error logging activity:", error);
  }
};

// Error handler middleware
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: "Something went wrong!",
    message: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
};

// ========== ROUTES ==========

// ===== PUBLIC ROUTES =====

// GET all terms with pagination, search, and filters
app.get("/api/terms", async (req, res) => {
  try {
    const {
      page = 1,
      limit = 1000, // ИЗМЕНЕНО: увеличен лимит по умолчанию
      search = "",
      theme = "all",
      sortBy = "term_kaa",
      order = "asc",
    } = req.query;

    // Build query
    let query = {};

    if (search) {
      query.$or = [
        { term_kaa: { $regex: search, $options: "i" } },
        { term_en: { $regex: search, $options: "i" } },
        { definition_en: { $regex: search, $options: "i" } },
      ];
    }

    if (theme !== "all") {
      query.theme = theme;
    }

    // ИЗМЕНЕНО: добавлена проверка на limit
    const parsedLimit = parseInt(limit);
    const shouldPaginate = parsedLimit > 0 && parsedLimit < 10000;

    let terms;
    if (shouldPaginate) {
      // Execute query with pagination
      terms = await Term.find(query)
        .sort({ [sortBy]: order === "asc" ? 1 : -1 })
        .limit(parsedLimit)
        .skip((page - 1) * parsedLimit);
    } else {
      // Return all terms without pagination if limit is 0
      terms = await Term.find(query).sort({
        [sortBy]: order === "asc" ? 1 : -1,
      });
    }

    const count = await Term.countDocuments(query);

    res.json({
      data: terms,
      total: count,
      currentPage: shouldPaginate ? parseInt(page) : 1,
      totalPages: shouldPaginate ? Math.ceil(count / parsedLimit) : 1,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET single term by ID
app.get("/api/terms/:id", async (req, res) => {
  try {
    const term = await Term.findById(req.params.id);

    if (!term) {
      return res.status(404).json({ error: "Term not found" });
    }

    // Increment view count
    term.views += 1;
    await term.save();

    res.json(term);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET all themes
app.get("/api/themes", async (req, res) => {
  try {
    // Сортируем сначала по order, затем по created_at
    const themes = await Theme.find().sort({ order: 1, created_at: 1 });

    // Update term counts
    for (let theme of themes) {
      const count = await Term.countDocuments({ theme: theme.name_en });
      theme.terms_count = count;
    }

    res.json(themes);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET quiz questions
app.get("/api/quiz", async (req, res) => {
  try {
    const { type, theme = "all", count = 10 } = req.query;

    // Build query
    let query = {};
    if (theme !== "all") {
      query.theme = theme;
    }

    // Get random terms
    const terms = await Term.aggregate([
      { $match: query },
      { $sample: { size: parseInt(count) * 4 } }, // Get extra for options
    ]);

    if (terms.length < count) {
      return res.status(400).json({
        error: "Not enough terms for quiz",
        required: count,
        available: terms.length,
      });
    }

    // Generate questions based on type
    const questions = [];
    const selectedTerms = terms.slice(0, count);

    for (let i = 0; i < selectedTerms.length; i++) {
      const term = selectedTerms[i];
      const otherTerms = terms.filter(
        (t) => t._id.toString() !== term._id.toString()
      );

      let question = {
        id: i + 1,
        term_id: term._id,
      };

      switch (type) {
        case "translation_kaa_en":
          question.question = `Translate to English: "${term.term_kaa}"`;
          question.correctAnswer = term.term_en;
          question.options = generateOptions(
            term.term_en,
            otherTerms.map((t) => t.term_en)
          );
          break;

        case "translation_en_kaa":
          question.question = `Translate to Karakalpak: "${term.term_en}"`;
          question.correctAnswer = term.term_kaa;
          question.options = generateOptions(
            term.term_kaa,
            otherTerms.map((t) => t.term_kaa)
          );
          break;

        case "definition":
          question.question = `Which term matches this definition: "${term.definition_en}"`;
          question.correctAnswer = term.term_en;
          question.options = generateOptions(
            term.term_en,
            otherTerms.map((t) => t.term_en)
          );
          break;

        case "multiple":
          const isKaaQuestion = Math.random() > 0.5;
          if (isKaaQuestion) {
            question.question = `What is the English translation of "${term.term_kaa}"?`;
            question.correctAnswer = term.term_en;
            question.options = generateOptions(
              term.term_en,
              otherTerms.map((t) => t.term_en)
            );
          } else {
            question.question = `What is the Karakalpak translation of "${term.term_en}"?`;
            question.correctAnswer = term.term_kaa;
            question.options = generateOptions(
              term.term_kaa,
              otherTerms.map((t) => t.term_kaa)
            );
          }
          break;

        default:
          question.question = `Translate: ${term.term_kaa}`;
          question.correctAnswer = term.term_en;
          question.options = generateOptions(
            term.term_en,
            otherTerms.map((t) => t.term_en)
          );
      }

      questions.push(question);
    }

    res.json({ data: questions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function to generate options
function generateOptions(correct, pool, count = 4) {
  const options = [correct];
  const shuffled = pool
    .filter((item) => item !== correct)
    .sort(() => 0.5 - Math.random());

  for (let i = 0; i < count - 1 && i < shuffled.length; i++) {
    if (!options.includes(shuffled[i])) {
      options.push(shuffled[i]);
    }
  }

  return options.sort(() => 0.5 - Math.random());
}

// POST quiz result
app.post("/api/quiz/result", async (req, res) => {
  try {
    const result = await QuizResult.create(req.body);

    // Log activity
    await logActivity(
      "quiz_completed",
      "quiz",
      result._id,
      req.body.session_id,
      req
    );

    res.json({ success: true, data: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET quiz history
app.get("/api/quiz/history", async (req, res) => {
  try {
    const { session_id, limit = 50 } = req.query;

    if (!session_id) {
      return res.json([]);
    }

    const results = await QuizResult.find({ session_id })
      .sort("-created_at")
      .limit(parseInt(limit));

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET quiz statistics
app.get("/api/quiz/stats", async (req, res) => {
  try {
    const { session_id } = req.query;

    let query = {};
    if (session_id) {
      query.session_id = session_id;
    }

    const stats = await QuizResult.aggregate([
      { $match: query },
      {
        $group: {
          _id: null,
          totalQuizzes: { $sum: 1 },
          averageScore: { $avg: "$percentage" },
          totalQuestions: { $sum: "$total_questions" },
          totalCorrect: { $sum: "$correct_answers" },
          averageTime: { $avg: "$time_spent" },
        },
      },
    ]);

    const themeStats = await QuizResult.aggregate([
      { $match: query },
      {
        $group: {
          _id: "$theme",
          count: { $sum: 1 },
          averageScore: { $avg: "$percentage" },
        },
      },
    ]);

    res.json({
      overall: stats[0] || {},
      byTheme: themeStats,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET popular terms
app.get("/api/stats/popular", async (req, res) => {
  try {
    const popularTerms = await Term.find()
      .sort("-views")
      .limit(20)
      .select("term_kaa term_en theme views");

    res.json(popularTerms);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== ADMIN ROUTES =====

// Admin login
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    console.log("Login attempt for username:", username); // Debug log

    // Find admin
    const admin = await Admin.findOne({ username });

    if (!admin) {
      console.log("Admin not found"); // Debug log
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, admin.password);

    if (!isMatch) {
      console.log("Password mismatch"); // Debug log
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Update last login
    admin.last_login = new Date();
    await admin.save();

    // Generate token
    const token = jwt.sign(
      { id: admin._id, username: admin.username },
      process.env.JWT_SECRET ||
        "your_super_secret_jwt_key_change_this_in_production",
      { expiresIn: process.env.JWT_EXPIRE || "30d" }
    );

    // Log activity
    await logActivity("admin_login", "admin", admin._id, admin.username, req);

    console.log("Login successful, token generated"); // Debug log

    res.json({
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        role: admin.role,
      },
    });
  } catch (error) {
    console.error("Login error:", error); // Debug log
    res.status(500).json({ error: error.message });
  }
});

// Verify admin token
app.get("/api/admin/verify", authenticateAdmin, (req, res) => {
  res.json({
    valid: true,
    admin: {
      id: req.admin._id,
      username: req.admin.username,
      role: req.admin.role,
    },
  });
});

// Create new term (admin only)
app.post("/api/admin/terms", authenticateAdmin, async (req, res) => {
  try {
    const term = await Term.create({
      ...req.body,
      created_by: req.admin.username,
    });

    // Update theme count
    await Theme.updateOne(
      { name_en: term.theme },
      { $inc: { terms_count: 1 } }
    );

    // Log activity
    await logActivity(
      "term_created",
      "term",
      term._id,
      req.admin.username,
      req
    );

    res.json({ success: true, data: term });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update term (admin only)
app.put("/api/admin/terms/:id", authenticateAdmin, async (req, res) => {
  try {
    const oldTerm = await Term.findById(req.params.id);

    if (!oldTerm) {
      return res.status(404).json({ error: "Term not found" });
    }

    // Update term
    const term = await Term.findByIdAndUpdate(
      req.params.id,
      { ...req.body, updated_at: new Date() },
      { new: true }
    );

    // Update theme counts if theme changed
    if (oldTerm.theme !== term.theme) {
      await Theme.updateOne(
        { name_en: oldTerm.theme },
        { $inc: { terms_count: -1 } }
      );
      await Theme.updateOne(
        { name_en: term.theme },
        { $inc: { terms_count: 1 } }
      );
    }

    // Log activity
    await logActivity(
      "term_updated",
      "term",
      term._id,
      req.admin.username,
      req
    );

    res.json({ success: true, data: term });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete term (admin only)
app.delete("/api/admin/terms/:id", authenticateAdmin, async (req, res) => {
  try {
    const term = await Term.findById(req.params.id);

    if (!term) {
      return res.status(404).json({ error: "Term not found" });
    }

    await term.deleteOne();

    // Update theme count
    await Theme.updateOne(
      { name_en: term.theme },
      { $inc: { terms_count: -1 } }
    );

    // Log activity
    await logActivity(
      "term_deleted",
      "term",
      req.params.id,
      req.admin.username,
      req
    );

    res.json({ success: true, message: "Term deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Bulk import terms from CSV (admin only)
app.post(
  "/api/admin/terms/import",
  authenticateAdmin,
  upload.single("file"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    console.log("Import file received:", req.file.filename);
    console.log("File path:", req.file.path);

    const results = [];
    const errors = [];
    const duplicates = [];
    let imported = 0;
    let failed = 0;
    let skipped = 0;
    let rowCount = 0;

    try {
      // Check if file exists
      if (!fs.existsSync(req.file.path)) {
        console.error("File not found:", req.file.path);
        return res.status(500).json({ error: "Uploaded file not found" });
      }

      const stream = fs.createReadStream(req.file.path);
      const csvStream = csv({
        mapHeaders: ({ header }) => header.trim(), // Remove spaces from headers
        quote: '"', // Указываем символ кавычек
        escape: '"', // Экранирование кавычек
        delimiter: ",", // Разделитель - запятая
        skipLinesWithError: false, // Не пропускать строки с ошибками
      });

      const promises = [];

      csvStream
        .on("data", (data) => {
          rowCount++;
          console.log(`Processing row ${rowCount}:`, data);

          // Clean up data
          const cleanData = {};
          for (let key in data) {
            cleanData[key.trim()] = data[key] ? data[key].trim() : "";
          }

          // Check for required fields
          if (!cleanData.term_kaa || !cleanData.term_en || !cleanData.theme) {
            console.error(
              `Row ${rowCount} missing required fields:`,
              cleanData
            );
            errors.push({
              row: rowCount,
              data: cleanData,
              error: "Missing required fields (term_kaa, term_en, or theme)",
            });
            failed++;
            return;
          }

          // Create term promise with duplicate check
          const promise = (async () => {
            try {
              // Проверяем, существует ли уже такой термин
              const existingTerm = await Term.findOne({
                $or: [
                  { term_kaa: cleanData.term_kaa, term_en: cleanData.term_en },
                  { term_kaa: cleanData.term_kaa, theme: cleanData.theme },
                  { term_en: cleanData.term_en, theme: cleanData.theme },
                ],
              });

              if (existingTerm) {
                console.log(
                  `Duplicate found for row ${rowCount}: ${cleanData.term_kaa} / ${cleanData.term_en}`
                );
                duplicates.push({
                  row: rowCount,
                  term_kaa: cleanData.term_kaa,
                  term_en: cleanData.term_en,
                  theme: cleanData.theme,
                });
                skipped++;
                return;
              }

              // Создаем новый термин
              const term = await Term.create({
                term_kaa: cleanData.term_kaa,
                term_en: cleanData.term_en,
                definition_en: cleanData.definition_en || "Definition pending",
                definition_kaa: cleanData.definition_kaa || "",
                theme: cleanData.theme,
                created_by: req.admin.username,
              });

              imported++;
              results.push(term);
              console.log(`Successfully imported: ${term.term_en}`);
            } catch (error) {
              failed++;
              errors.push({
                row: rowCount,
                data: cleanData,
                error: error.message,
              });
              console.error(`Failed to import row ${rowCount}:`, error.message);
            }
          })();

          promises.push(promise);
        })
        .on("end", async () => {
          console.log(`CSV parsing complete. Total rows: ${rowCount}`);

          // Wait for all database operations to complete
          await Promise.all(promises);

          // Delete uploaded file
          try {
            fs.unlinkSync(req.file.path);
            console.log("Temporary file deleted");
          } catch (err) {
            console.error("Error deleting temp file:", err);
          }

          // Update theme counts
          const themes = await Theme.find();
          for (let theme of themes) {
            const count = await Term.countDocuments({ theme: theme.name_en });
            theme.terms_count = count;
            await theme.save();
          }

          console.log(
            `Import complete: ${imported} imported, ${skipped} skipped, ${failed} failed`
          );

          res.json({
            success: true,
            message: `Import complete: ${imported} terms imported, ${skipped} duplicates skipped, ${failed} failed`,
            imported,
            skipped,
            failed,
            totalRows: rowCount,
            duplicates: duplicates.slice(0, 5), // Первые 5 дубликатов
            errors: errors.slice(0, 10), // Return first 10 errors for debugging
          });
        })
        .on("error", (error) => {
          console.error("CSV parsing error:", error);

          // Try to delete file if it exists
          try {
            if (fs.existsSync(req.file.path)) {
              fs.unlinkSync(req.file.path);
            }
          } catch (err) {
            console.error("Error deleting temp file:", err);
          }

          res.status(500).json({
            error: "CSV parsing failed",
            message: error.message,
          });
        });

      stream.pipe(csvStream);
    } catch (error) {
      console.error("Import error:", error);

      // Try to delete file if it exists
      try {
        if (req.file && fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
      } catch (err) {
        console.error("Error deleting temp file:", err);
      }

      res.status(500).json({
        error: "Import failed",
        message: error.message,
      });
    }
  }
);

// Create theme (admin only)
app.post("/api/admin/themes", authenticateAdmin, async (req, res) => {
  try {
    // Извлекаем номер из имени темы если есть
    const match = req.body.name_en.match(/\d+/);
    let order;

    if (match) {
      order = parseInt(match[0]);
    } else {
      // Если нет номера, находим максимальный order и добавляем 1
      const maxTheme = await Theme.findOne().sort("-order");
      order = maxTheme ? maxTheme.order + 1 : 1000;
    }

    const theme = await Theme.create({
      ...req.body,
      order: order,
    });

    // Log activity
    await logActivity(
      "theme_created",
      "theme",
      theme._id,
      req.admin.username,
      req
    );

    res.json({ success: true, data: theme });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update theme (admin only)
app.put("/api/admin/themes/:id", authenticateAdmin, async (req, res) => {
  try {
    const oldTheme = await Theme.findById(req.params.id);

    if (!oldTheme) {
      return res.status(404).json({ error: "Theme not found" });
    }

    const theme = await Theme.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });

    // If name changed, update all terms
    if (oldTheme.name_en !== theme.name_en) {
      await Term.updateMany(
        { theme: oldTheme.name_en },
        { theme: theme.name_en }
      );
    }

    // Log activity
    await logActivity(
      "theme_updated",
      "theme",
      theme._id,
      req.admin.username,
      req
    );

    res.json({ success: true, data: theme });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete theme (admin only)
app.delete("/api/admin/themes/:id", authenticateAdmin, async (req, res) => {
  try {
    const theme = await Theme.findById(req.params.id);

    if (!theme) {
      return res.status(404).json({ error: "Theme not found" });
    }

    // Check if theme has terms
    const termsCount = await Term.countDocuments({
      theme: theme.name_en,
    });

    if (termsCount > 0) {
      return res.status(400).json({
        error: `Cannot delete theme with ${termsCount} terms. Please reassign or delete terms first.`,
      });
    }

    await theme.deleteOne();

    // Log activity
    await logActivity(
      "theme_deleted",
      "theme",
      req.params.id,
      req.admin.username,
      req
    );

    res.json({ success: true, message: "Theme deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/", async (req, res) => {
  res.send("Welcome to the AgroLex API");
});

// Get admin statistics
app.get("/api/admin/stats", authenticateAdmin, async (req, res) => {
  try {
    const totalTerms = await Term.countDocuments();
    const totalThemes = await Theme.countDocuments();
    const totalQuizzes = await QuizResult.countDocuments();

    // Get recent activity
    const recentActivity = await Activity.find().sort("-created_at").limit(10);

    // Get daily stats for last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const dailyQuizzes = await QuizResult.aggregate([
      { $match: { created_at: { $gte: sevenDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$created_at" } },
          count: { $sum: 1 },
          avgScore: { $avg: "$percentage" },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    res.json({
      data: {
        totalTerms,
        totalThemes,
        totalQuizzes,
        recentActivity,
        dailyQuizzes,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get search analytics (admin only)
app.get("/api/admin/analytics", authenticateAdmin, async (req, res) => {
  try {
    // Most viewed terms
    const popularTerms = await Term.find()
      .sort("-views")
      .limit(10)
      .select("term_kaa term_en theme views");

    // Theme distribution
    const themeStats = await Term.aggregate([
      {
        $group: {
          _id: "$theme",
          count: { $sum: 1 },
          avgViews: { $avg: "$views" },
        },
      },
      { $sort: { count: -1 } },
    ]);

    // Quiz performance by type
    const quizTypeStats = await QuizResult.aggregate([
      {
        $group: {
          _id: "$quiz_type",
          count: { $sum: 1 },
          avgScore: { $avg: "$percentage" },
          avgTime: { $avg: "$time_spent" },
        },
      },
    ]);

    res.json({
      popularTerms,
      themeStats,
      quizTypeStats,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ERROR HANDLING ==========
app.use(errorHandler);

// ========== DATABASE CONNECTION & SERVER START ==========
const PORT = process.env.PORT || 4321;

mongoose
  .connect(
    process.env.MONGODB_URI || "mongodb://localhost:27017/agro-dictionary",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  )
  .then(async () => {
    console.log("✅ MongoDB connected successfully");
    console.log("⚠️  RATE LIMITING IS DISABLED FOR DEVELOPMENT!");

    // Create default admin if not exists
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const hashedPassword = await bcrypt.hash(
        process.env.ADMIN_PASSWORD || "admin123",
        10
      );
      await Admin.create({
        username: process.env.ADMIN_USERNAME || "admin",
        password: hashedPassword,
        role: "admin",
      });
      console.log(
        "✅ Default admin created (username: admin, password: admin123)"
      );
    }

    // Start server
    app.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`📍 API URL: http://localhost:${PORT}/api`);
      console.log(`🔧 Environment: ${process.env.NODE_ENV || "development"}`);
    });
  })
  .catch((error) => {
    console.error("❌ MongoDB connection error:", error);
    process.exit(1);
  });

// ========== GRACEFUL SHUTDOWN ==========
process.on("SIGINT", async () => {
  console.log("\n🛑 Shutting down gracefully...");
  await mongoose.connection.close();
  process.exit(0);
});
