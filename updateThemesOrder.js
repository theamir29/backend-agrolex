// updateThemesOrder.js
// Скрипт для обновления порядка тем на основе их имен

require("dotenv").config();
const mongoose = require("mongoose");

// Определяем схему темы (должна соответствовать схеме в server.js)
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

const Theme = mongoose.model("Theme", themeSchema);

async function updateThemesOrder() {
  try {
    // Подключаемся к MongoDB
    await mongoose.connect(
      process.env.MONGODB_URI || "mongodb://localhost:27017/agro-dictionary",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log("✅ Connected to MongoDB");

    // Получаем все темы
    const themes = await Theme.find().sort("name_en");
    console.log(`📊 Found ${themes.length} themes`);

    // Обновляем порядок для каждой темы
    for (let i = 0; i < themes.length; i++) {
      const theme = themes[i];

      // Извлекаем номер из имени темы (например, "Topic 1" -> 1)
      const match = theme.name_en.match(/\d+/);
      let order;

      if (match) {
        // Если есть номер в названии, используем его
        order = parseInt(match[0]);
      } else {
        // Если нет номера, ставим в конец (1000 + индекс)
        order = 1000 + i;
      }

      // Обновляем и сохраняем
      theme.order = order;
      await theme.save();
      console.log(`✨ Updated "${theme.name_en}" with order ${order}`);
    }

    console.log("\n✅ All themes updated successfully!");

    // Показываем итоговый порядок
    console.log("\n📋 Final order:");
    const sortedThemes = await Theme.find().sort({ order: 1 });
    sortedThemes.forEach((theme, index) => {
      console.log(`  ${index + 1}. ${theme.name_en} (order: ${theme.order})`);
    });
  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  } finally {
    // Отключаемся от MongoDB
    await mongoose.disconnect();
    console.log("\n👋 Disconnected from MongoDB");
  }
}

// Запускаем функцию
updateThemesOrder();
