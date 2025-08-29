require("dotenv").config();
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

// Подключаемся к MongoDB
mongoose
  .connect(
    process.env.MONGODB_URI || "mongodb://localhost:27017/agro-dictionary"
  )
  .then(() => {
    // Создаем тестовый токен
    const token = jwt.sign(
      { id: "testadmin", username: "admin" },
      process.env.JWT_SECRET ||
        "your_super_secret_jwt_key_change_this_in_production",
      { expiresIn: "30d" }
    );

    console.log("\n===========================================");
    console.log("Тестовый токен для админа:");
    console.log(token);
    console.log("\n1. Откройте браузер DevTools (F12)");
    console.log("2. Перейдите в Console");
    console.log("3. Выполните эти команды:");
    console.log(`localStorage.setItem("adminToken", "${token}");`);
    console.log('localStorage.setItem("isAdmin", "true");');
    console.log("4. Обновите страницу");
    console.log("===========================================\n");

    process.exit(0);
  });
