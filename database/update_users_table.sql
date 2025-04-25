-- Добавляем новые поля в таблицу users
ALTER TABLE users
ADD COLUMN age VARCHAR(50) NOT NULL DEFAULT '',
ADD COLUMN salary INTEGER NOT NULL DEFAULT '',
ADD COLUMN hobby VARCHAR(50);

-- Обновляем существующие записи
UPDATE users
SET first_name = split_part(username, ' ', 1),
    last_name = split_part(username, ' ', 2),
    middle_name = CASE 
        WHEN array_length(string_to_array(username, ' '), 1) > 2 
        THEN split_part(username, ' ', 3) 
        ELSE NULL 
    END; 