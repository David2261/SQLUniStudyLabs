from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


db = SQLAlchemy()


class Role(db.Model):
	__tablename__ = 'roles'

	id = db.Column(db.Integer, primary_key=True)
	role_name = db.Column(db.String(50), nullable=False, unique=True)
	users = db.relationship('User', back_populates='role')

	def __repr__(self):
		return f'<Role {self.role_name}>'


class User(UserMixin, db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique=True, nullable=False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	password_hash = db.Column(db.String(128))
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
	is_active = db.Column(db.Boolean, default=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow)
	updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
	
	# Личные данные
	first_name = db.Column(db.String(64))
	middle_name = db.Column(db.String(64))
	last_name = db.Column(db.String(64))
	
	# Связи
	role = db.relationship('Role', back_populates='users')
	products = db.relationship('Product', backref='creator', lazy=True)
	cart_items = db.relationship('Cart', backref='user', lazy=True)
	
	# Связи с заказами
	orders_as_customer = db.relationship('Order', 
									   foreign_keys='Order.user_id',
									   back_populates='customer',
									   lazy=True)
	orders_as_seller = db.relationship('Order',
									 foreign_keys='Order.seller_id',
									 back_populates='seller',
									 lazy=True)
	
	supplier = db.relationship('Supplier', backref='user', uselist=False, lazy=True)

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)

	def __repr__(self):
		return f'<User {self.username}>'


class Category(db.Model):
	__tablename__ = 'categories'

	id = db.Column(db.Integer, primary_key=True)
	category_name = db.Column(db.String(100), nullable=False)
	category_description = db.Column(db.Text)
	products = db.relationship('Product', backref='category', lazy=True)


class Supplier(db.Model):
	__tablename__ = 'suppliers'

	id = db.Column(db.Integer, primary_key=True)
	supplier_name = db.Column(db.String(100), nullable=False)
	contact_info = db.Column(db.Text)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	products = db.relationship('Product', backref='supplier', lazy=True)


class Product(db.Model):
	__tablename__ = 'products'

	id = db.Column(db.Integer, primary_key=True)
	productname = db.Column(db.String(100), nullable=False)
	price = db.Column(db.Numeric(10, 2), nullable=False)
	category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
	supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=False)
	product_image = db.Column(db.String(255))
	is_published = db.Column(db.Boolean, default=False)
	created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	created_at = db.Column(db.DateTime, default=datetime.utcnow)
	
	# Связи
	cart_items = db.relationship('Cart', backref='product', lazy=True)
	order_items = db.relationship('OrderItem', back_populates='product', lazy=True)

	def __repr__(self):
		return f'<Product {self.productname}>'


class Cart(db.Model):
	__tablename__ = 'cart'

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
	quantity = db.Column(db.Integer, default=1)
	created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Order(db.Model):
	__tablename__ = 'orders'

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	total_amount = db.Column(db.Numeric(10, 2), nullable=False)
	status = db.Column(db.String(50), nullable=False, default='pending')
	created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	
	# Связи
	order_items = db.relationship('OrderItem', back_populates='order', lazy=True)
	customer = db.relationship('User', foreign_keys=[user_id], back_populates='orders_as_customer')
	seller = db.relationship('User', foreign_keys=[seller_id], back_populates='orders_as_seller')

	def __repr__(self):
		return f'<Order {self.id}>'


class OrderItem(db.Model):
	__tablename__ = 'order_items'

	id = db.Column(db.Integer, primary_key=True)
	order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
	product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
	quantity = db.Column(db.Integer, nullable=False)
	price = db.Column(db.Numeric(10, 2), nullable=False)
	created_at = db.Column(db.DateTime, default=datetime.utcnow)

	# Связи
	product = db.relationship('Product', back_populates='order_items')
	order = db.relationship('Order', back_populates='order_items')

	def __repr__(self):
		return f'<OrderItem {self.id}>'


class UserRole(db.Model):
	__tablename__ = 'user_roles'

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'))


class Address(db.Model):
	__tablename__ = 'addresses'

	id = db.Column(db.Integer, primary_key=True)
	region = db.Column(db.String(100))
	city = db.Column(db.String(100))
	postal_code = db.Column(db.String(20))
	street = db.Column(db.String(100))
	house_number = db.Column(db.String(10))
	user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))


class Delivery(db.Model):
	__tablename__ = 'deliveries'

	id = db.Column(db.Integer, primary_key=True)
	delivery_method_id = db.Column(db.Integer, db.ForeignKey('delivery_methods.id'))
	delivery_status_id = db.Column(db.Integer, db.ForeignKey('delivery_statuses.id'))
	tracking_number = db.Column(db.String(50), unique=True)
	shipment_date = db.Column(db.Date)
	delivery_date = db.Column(db.Date)
	order_id = db.Column(db.Integer, db.ForeignKey('orders.id', ondelete='CASCADE'))


class DeliveryMethod(db.Model):
	__tablename__ = 'delivery_methods'
	
	id = db.Column(db.Integer, primary_key=True)
	delivery_method_name = db.Column(db.String(100), nullable=False)
	delivery_method_description = db.Column(db.Text)
	price = db.Column(db.Numeric(10, 2), nullable=False)


class DeliveryStatus(db.Model):
	__tablename__ = 'delivery_statuses'

	id = db.Column(db.Integer, primary_key=True)
	delivery_status_name = db.Column(db.String(100), nullable=False)
	delivery_status_description = db.Column(db.Text)


class Payment(db.Model):
	__tablename__ = 'payments'

	id = db.Column(db.Integer, primary_key=True)
	payment_date = db.Column(db.DateTime, default=db.func.current_timestamp())
	amount = db.Column(db.Numeric(10, 2), nullable=False)
	payment_method = db.Column(db.String(50))
	order_id = db.Column(db.Integer, db.ForeignKey('orders.id', ondelete='SET NULL'))
	payment_status_id = db.Column(db.Integer, db.ForeignKey('payment_statuses.id'))


class PaymentStatus(db.Model):
	__tablename__ = 'payment_statuses'

	id = db.Column(db.Integer, primary_key=True)
	payment_status_name = db.Column(db.String(100), nullable=False)
	payment_status_description = db.Column(db.Text)


class Review(db.Model):
    __tablename__ = 'reviews'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    order_detail_id = db.Column(db.Integer, db.ForeignKey('order_details.id'))
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
