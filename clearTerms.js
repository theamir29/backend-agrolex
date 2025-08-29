require("dotenv").config();
const mongoose = require("mongoose");

const termSchema = new mongoose.Schema({
  term_kaa: String,
  term_en: String,
  definition_en: String,
  definition_kaa: String,
  theme: String,
  audio_url: String,
  views: Number,
  favorites_count: Number,
  created_by: String,
  created_at: Date,
  updated_at: Date,
});

const Term = mongoose.model("Term", termSchema);

async function clearTerms() {
  try {
    await mongoose.connect(
      process.env.MONGODB_URI || "mongodb://localhost:27017/agro-dictionary"
    );
    console.log("Connected to MongoDB");

    const result = await Term.deleteMany({});
    console.log(`Deleted ${result.deletedCount} terms`);
  } catch (error) {
    console.error("Error:", error);
  } finally {
    await mongoose.disconnect();
    console.log("Disconnected from MongoDB");
  }
}

clearTerms();
