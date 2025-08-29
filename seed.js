require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// ========== SCHEMAS ==========
const termSchema = new mongoose.Schema({
  term_kaa: { type: String, required: true, trim: true, index: true },
  term_en: { type: String, required: true, trim: true, index: true },
  definition_en: { type: String, required: true },
  definition_kaa: { type: String, default: "" },
  theme: { type: String, required: true, index: true },
  audio_url: { type: String, default: "" },
  views: { type: Number, default: 0 },
  favorites_count: { type: Number, default: 0 },
  created_by: { type: String, default: "system" },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
});

const themeSchema = new mongoose.Schema({
  name_en: { type: String, required: true, unique: true },
  name_kaa: { type: String, required: true },
  description: { type: String, default: "" },
  terms_count: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now },
});

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "admin" },
  last_login: Date,
  created_at: { type: Date, default: Date.now },
});

// Models
const Term = mongoose.model("Term", termSchema);
const Theme = mongoose.model("Theme", themeSchema);
const Admin = mongoose.model("Admin", adminSchema);

// ========== SEED FUNCTION ==========
async function seedDatabase() {
  try {
    // Connect to MongoDB
    await mongoose.connect(
      process.env.MONGODB_URI || "mongodb://localhost:27017/agro-dictionary",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log("✅ Connected to MongoDB");

    // Clear existing data
    console.log("🗑️  Clearing existing data...");
    await Term.deleteMany({});
    await Theme.deleteMany({});
    await Admin.deleteMany({});

    // Create admin
    console.log("👤 Creating admin user...");
    const hashedPassword = await bcrypt.hash(
      process.env.ADMIN_PASSWORD || "admin123",
      10
    );
    await Admin.create({
      username: process.env.ADMIN_USERNAME || "admin",
      password: hashedPassword,
      role: "admin",
    });
    console.log("✅ Admin created (username: admin, password: admin123)");

    console.log("✅ Database cleared and admin created!");
    console.log(`
    Summary:
    - All data cleared
    - Admin created: username: admin, password: admin123
    - You can now add themes and terms through the admin panel
    `);
  } catch (error) {
    console.error("❌ Error seeding database:", error);
  } finally {
    await mongoose.connection.close();
    console.log("👋 Database connection closed");
  }
}

// Run seed
seedDatabase();
