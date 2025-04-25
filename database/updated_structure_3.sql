-- Добавление новых столбцов в таблицу "products"
ALTER TABLE products 
ADD COLUMN description TEXT,
ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN stock_quantity INT DEFAULT 0;

-- Изменение типа данных в таблице "payments" (уменьшение длины строки статуса)
ALTER TABLE payments 
ALTER COLUMN payment_status TYPE VARCHAR(20);

-- Изменение типа данных для суммы платежа на более точный тип
ALTER TABLE payments 
ALTER COLUMN amount TYPE DECIMAL(10, 2);

-- Удаление столбца "phone" у пользователей
ALTER TABLE users 
DROP COLUMN phone;

-- Удаление столбца "middle_name" у пользователей
ALTER TABLE users 
DROP COLUMN middle_name;

-- Добавление ограничения NOT NULL для столбца email
ALTER TABLE users 
ALTER COLUMN email SET NOT NULL;

-- Добавление индекса на столбец email в таблице users
CREATE INDEX idx_users_email ON users(email);

-- Добавление индекса на столбец created_at в таблице products
CREATE INDEX idx_products_created_at ON products(created_at);

-- Добавление ограничения уникальности на столбец email в таблице users
ALTER TABLE users 
ADD CONSTRAINT unique_email UNIQUE (email);

-- Добавление ограничения уникальности на столбец productname в таблице products
ALTER TABLE products 
ADD CONSTRAINT unique_productname UNIQUE (productname);