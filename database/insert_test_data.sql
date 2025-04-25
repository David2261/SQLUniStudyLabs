\c shop_db;

-- Очищаем таблицы в правильном порядке
-- TRUNCATE TABLE reviews CASCADE;
-- TRUNCATE TABLE order_details CASCADE;
-- TRUNCATE TABLE order_items CASCADE;
-- TRUNCATE TABLE orders CASCADE;
-- TRUNCATE TABLE cart CASCADE;
-- TRUNCATE TABLE products CASCADE;
-- TRUNCATE TABLE suppliers CASCADE;
-- TRUNCATE TABLE users CASCADE;
-- TRUNCATE TABLE categories CASCADE;
-- TRUNCATE TABLE roles CASCADE;


-- Вставляем пользователей
INSERT INTO users (username, email, password_hash, role_id, is_active, first_name, last_name, middle_name) VALUES
('admin', 'admin@example.com', 'pbkdf2:sha256:600000$GX7s4vLx$c4c5c6c7c8c9c10c11c12c13c14c15c16c17c18c19c20', 1, TRUE, 'Иван', 'Иванов', 'Иванович'),
('seller', 'seller@example.com', 'pbkdf2:sha256:600000$GX7s4vLx$c4c5c6c7c8c9c10c11c12c13c14c15c16c17c18c19c20', 2, TRUE, 'Петр', 'Петров', 'Петрович'),
('user', 'user@example.com', 'pbkdf2:sha256:600000$GX7s4vLx$c4c5c6c7c8c9c10c11c12c13c14c15c16c17c18c19c20', 3, TRUE, 'Сергей', 'Сергеев', 'Сергеевич');

-- Вставляем категории
INSERT INTO categories (id, category_name, category_description) VALUES
(1, 'Электроника', 'Электронные устройства и гаджеты'),
(2, 'Одежда', 'Мужская и женская одежда'),
(3, 'Книги', 'Художественная и учебная литература'),
(4, 'Спорт', 'Спортивные товары и инвентарь');

-- Вставляем поставщиков
INSERT INTO suppliers (id, supplier_name, contact_info, user_id) VALUES
(1, 'TechSupplier', 'tech@example.com', 2),
(2, 'FashionSupplier', 'fashion@example.com', 2),
(3, 'BookSupplier', 'books@example.com', 2),
(4, 'SportSupplier', 'sport@example.com', 2);

-- Вставляем товары
INSERT INTO products (id, productname, price, category_id, supplier_id, product_image, quantity, is_published, created_by) VALUES
(1, 'Смартфон', 29999.99, 1, 1, '/static/images/smartphone.jpg', 10, TRUE, 2),
(2, 'Ноутбук', 59999.99, 1, 1, '/static/images/laptop.jpg', 5, TRUE, 2),
(3, 'Футболка', 1999.99, 2, 2, '/static/images/tshirt.jpg', 20, TRUE, 2),
(4, 'Джинсы', 3999.99, 2, 2, '/static/images/jeans.jpg', 15, TRUE, 2),
(5, 'Роман', 599.99, 3, 3, '/static/images/book.jpg', 30, TRUE, 2),
(6, 'Учебник', 999.99, 3, 3, '/static/images/textbook.jpg', 25, TRUE, 2),
(7, 'Мяч', 1499.99, 4, 4, '/static/images/ball.jpg', 40, TRUE, 2),
(8, 'Гантели', 2999.99, 4, 4, '/static/images/dumbbells.jpg', 20, TRUE, 2),
(9, 'Наушники', 4999.99, 1, 1, '/static/images/headphones.jpg', 15, TRUE, 2),
(10, 'Кроссовки', 4999.99, 2, 2, '/static/images/sneakers.jpg', 10, TRUE, 2),
(11, 'Adidas shoes', 2599.99, 2, 2, '/static/images/20250407_025226_Adidas_samba_vegan_1_.jpg', 10, TRUE, 2);