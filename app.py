from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import uuid
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/upload_products')
app.secret_key = 'aSecrETkEy'
db = SQLAlchemy(app)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    rating = db.Column(db.Float, nullable=False, default=0.0)
    num_ratings = db.Column(db.Integer, nullable=False, default=0)
    image_path = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text)
    latest_product = db.Column(db.Boolean, default=False)
    popular_product = db.Column(db.Boolean, default=False)
    comments = db.relationship('Comment', backref='product', lazy=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)


class CommentForm(FlaskForm):
    comment = StringField('Comment', validators=[DataRequired()])
    submit = SubmitField('Add Comment')


# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


# Login form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


with app.app_context():
    db.create_all()

@app.context_processor
def inject_username():
    # Check if the user is logged in
    if 'username' in session:
        return {'username': session['username']}
    else:
        return {'username': None}

@app.route('/')
def home():
    latest_products = Product.query.filter_by(latest_product=True).all()
    popular_products = Product.query.filter_by(popular_product=True).all()
    return render_template('home.html', latest_products=latest_products, popular_products=popular_products)

@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def view_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = CommentForm()
    rating_form = RatingForm()

    if form.validate_on_submit():
        rating = int(request.form['rating'])
        comment = Comment(username=session['username'], product_id=product.id, comment=form.comment.data, rating=rating)

        # Update the product's rating and number of ratings
        update_stmt = update(Product).where(Product.id == product.id).values(
            rating=((Product.rating * Product.num_ratings) + rating) / (Product.num_ratings + 1),
            num_ratings=Product.num_ratings + 1
        )
        db.session.execute(update_stmt)
        db.session.add(comment)
        db.session.commit()
        flash('Comment and rating added successfully!', 'success')
        return redirect(url_for('view_product', product_id=product.id))

    if rating_form.validate_on_submit():
        rating = int(request.form['rating'])

        # Update the product's rating and number of ratings
        update_stmt = update(Product).where(Product.id == product.id).values(
            rating=((Product.rating * Product.num_ratings) + rating) / (Product.num_ratings + 1),
            num_ratings=Product.num_ratings + 1
        )
        db.session.execute(update_stmt)
        db.session.commit()
        flash('Rating submitted successfully!', 'success')
        return redirect(url_for('view_product', product_id=product.id))

    return render_template('product.html', product=product, form=form, rating_form=rating_form)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        description = request.form['description']
        latest_product = 'latest_product' in request.form
        popular_product = 'popular_product' in request.form

        image = request.files['image']
        if image:
            filename = secure_filename(image.filename)
            unique_filename = str(uuid.uuid4()) + '_' + filename
            image_path = os.path.join('upload_products/', unique_filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        else:
            image_path = None

        product = Product(name=name, price=price,
                          image_path=image_path, description=description,
                          latest_product=latest_product, popular_product=popular_product)
        db.session.add(product)
        db.session.commit()

        return redirect(url_for('admin'))

    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/store', methods=['GET'])
def store():
    search_query = request.args.get('search_query', '')
    filtered_products = filter_products(search_query)
    return render_template('store.html', products=filtered_products)

def filter_products(search_query):
    if search_query:
        return Product.query.filter(Product.name.ilike(f'%{search_query}%')).all()
    else:
        return Product.query.all()

@app.route('/admin/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.image_path:
        os.remove(os.path.join(app.static_folder, product.image_path))
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        product.name = request.form['name']
        product.price = float(request.form['price'])
        product.rating = float(request.form['rating'])
        product.comment = request.form['comment']
        product.description = request.form['description']
        product.latest_product = 'latest_product' in request.form
        product.popular_product = 'popular_product' in request.form

        image = request.files['image']
        if image:
            if product.image_path:
                os.remove(os.path.join(app.static_folder, product.image_path))
            filename = secure_filename(image.filename)
            unique_filename = str(uuid.uuid4()) + '_' + filename
            image_path = os.path.join('upload_products', unique_filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
            product.image_path = image_path

        db.session.commit()
        return redirect(url_for('admin'))

    return render_template('edit_product.html', product=product)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Check if the username or email already exists in the database
        existing_user = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()
        if existing_user:
            flash('Username or email already exists. Please choose a different one.', 'danger')
            return redirect('/register')

        # Create a new user
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect('/login')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if not user or user.password != password:
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect('/login')

        flash('Logged in successfully!', 'success')
        session['username'] = user.username
        return redirect('/')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    # Clear the session data
    session.clear()
    # Redirect to the home page or any other page after logout
    return redirect(url_for('home'))


if __name__ == '__main__':
    db.create_all()
    app.run()