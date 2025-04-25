-- Удаление заказа с каскадным удалением деталей заказа, платежей и отзывов
DELETE FROM orders 
WHERE id = 2;

-- Удалить связанные платежи и отзывы вручную
DELETE FROM payments WHERE order_id = 2;
DELETE FROM reviews WHERE order_detail_id IN (SELECT id FROM order_details WHERE order_id = 2);

-- Обновление статуса заказа с проверкой существования заказа
UPDATE orders 
SET order_status = 'delivered' 
WHERE id = 1 
AND EXISTS (SELECT 1 FROM orders WHERE id = 1);

-- Проверка успешного обновления
IF ROW_COUNT() = 0 THEN
    RAISE NOTICE 'Заказ с ID = 1 не найден или статус уже обновлен.';
END IF;

-- Обновление статуса заказа и запись в журнал
BEGIN;

UPDATE orders 
SET order_status = 'delivered' 
WHERE id = 1 
AND EXISTS (SELECT 1 FROM orders WHERE id = 1);

-- Запись в журнал изменений
INSERT INTO order_status_log (order_id, old_status, new_status, changed_at)
VALUES (1, (SELECT order_status FROM orders WHERE id = 1), 'delivered', NOW());

COMMIT;

-- Удаление заказа с уведомлением
DELETE FROM orders 
WHERE id = 2;

-- Уведомление о том, что заказ был удален
RAISE NOTICE 'Заказ с ID = 2 был успешно удален.';