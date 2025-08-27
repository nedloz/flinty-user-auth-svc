# 📌 Микросервис авторизации пользователей

## 📌 Описание проекта
**Название:** Микросервис авторизации пользователей  
**Стек:**  
- **Backend:** Node.js (Express), PostgreSQL, Redis  
- **Frontend:** (разрабатывается отдельно)  
- **Контейнеризация:** Docker  
- **Защита API:** JWT, CORS, Rate-Limiting  

📌 **Функциональность:**  
✅ **Регистрация / Вход / Выход**  
✅ **Refresh-токены (Redis)**  
✅ **Восстановление пароля (email + токен)**  
✅ **Удаление аккаунта**  
✅ **Безопасность (Rate-Limit, Helmet, CORS)**  

---

## 📌 API Эндпоинты (Auth Service)

### 🔹 1. Регистрация
`POST /auth/register`

**Тело запроса:**  
```json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "securepassword"
}
```

**Ответ:**  
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

### 🔹 2. Вход в систему
`POST /auth/login`

**Тело запроса:**  
```json
{
  "username": "testuser",
  "password": "securepassword"
}
```

**Ответ:**  
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "accessToken": "eyJhbGciOiJI...",
  "refreshToken": "dGhpcyBpcyBh..."
}
```

---

### 🔹 3. Обновление `accessToken`
`POST /auth/refresh`

**Тело запроса:**  
```json
{
  "refreshToken": "dGhpcyBpcyBh..."
}
```

**Ответ:**  
```json
{
  "accessToken": "new_access_token"
}
```

---

### 🔹 4. Восстановление пароля

📌 **Запросить сброс пароля**  
`POST /auth/forgot-password`

**Тело запроса:**  
```json
{
  "email": "test@example.com"
}
```

**Ответ:**  
```json
{
  "message": "Ссылка для восстановления пароля отправлена на email."
}
```

📌 **Сбросить пароль**  
`POST /auth/reset-password`

**Тело запроса:**  
```json
{
  "token": "reset_token_from_email",
  "newPassword": "newSecurePassword"
}
```

**Ответ:**  
```json
{
  "message": "Пароль успешно обновлён."
}
```

---

### 🔹 5. Выход из системы
`POST /auth/logout`

**Заголовки:**  
```json
Authorization: Bearer access_token
```

**Ответ:**  
```json
{
  "message": "Вы успешно вышли из системы."
}
```

---

### 🔹 6. Удаление аккаунта
`DELETE /auth/delete-account`

**Заголовки:**  
```json
Authorization: Bearer access_token
```

**Ответ:**  
```json
{
  "message": "Аккаунт успешно удалён"
}
```

---

## 📌 Запуск проекта

### 🔹 1. Установка зависимостей
```sh
npm install
```

### 🔹 2. Запуск сервера
```sh
npm start
```

### 🔹 3. Запуск в Docker
```sh
docker-compose up -d --build
```

---

## 📌 Что делать дальше?
1️⃣ **Использовать этот документ как основу для работы с `Auth Service`.**  
2️⃣ **Создать новый чат для фронтенда и подключить его к API.**  
3️⃣ **Развивать сервис, добавляя новые возможности.**  

🔥 **Готово! Теперь `Auth Service` полностью описан и готов к работе. 🚀**

