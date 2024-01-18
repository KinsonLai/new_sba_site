from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, LoginManager, login_required, login_user, UserMixin
from sqlalchemy import or_, desc
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from datetime import datetime
from googletrans import Translator
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import string

import nltk
nltk.download('punkt')
nltk.download('stopwords')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/upload_products')
app.config['SESSION_COOKIE_PATH'] = '/'
app.secret_key = 'aSecrETkEy'
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)

synonyms = {
    'founder': ['creator', 'owner', 'founder'],
    'sell': ['offer', 'sell', 'have', 'stock', 'supply', 'product'],
    'payment': ['payment', 'pay', 'credit', 'transaction'],
    'delivery': ['shipping', 'delivery', 'dispatch', 'mail'],
    'fee': ['charge', 'cost', 'fee', 'price'],
    'greeting': ['hi', 'hello', 'hey'],
    'thanks': ['thank', 'thanks', 'appreciate', 'grateful'],
    'farewell': ['bye', 'goodbye', 'see you']
}

# Define a function to process the input and find the best response
def generate_response(message):
    # Tokenize and lower the case of the message
    words = word_tokenize(message.lower())
    
    # Remove stopwords and punctuation
    words = [word for word in words if word not in stopwords.words('english') and word not in string.punctuation]

    # Check each word in the message for our keywords and respond accordingly
    for word in words:
        if word in synonyms['founder']:
            return "Our shop was founded by Jaygo."
        elif word in synonyms['sell']:
            return "We sell computers and electronic gadgets."
        elif word in synonyms['payment']:
            return "You can pay using credit card, Alipay, or Octopus Card."
        elif word in synonyms['delivery']:
            return "Your order will be delivered in 3 business days."
        elif word in synonyms['fee']:
            return "No delivery fee is needed, shipping is free!"
        elif word in synonyms['greeting']:
            return "Hello! How can I assist you today?"
        elif word in synonyms['thanks']:
            return "You're welcome! Let us know if there's anything else we can help with."
        elif word in synonyms['farewell']:
            return "Goodbye! Have a great day!"

    # Default response if no keywords are found
    return "Sorry, I'm not sure how to answer that. Can you ask something else?"

def translate_text(text, target_language):
    translator = Translator()
    result = translator.translate(text, dest=target_language)
    language_code_map = {
        'en': 'en',
        'fr': 'fr',
        'ja': 'ja',
        # Add more mappings as needed
    }
    googletrans_language = language_code_map.get(target_language)
    if googletrans_language is None:
        raise ValueError(f'Invalid language code: {target_language}')
    result = translator.translate(text, dest=googletrans_language)
    return result.text

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
    category = db.Column(db.String(100), nullable=False)

class Categories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired()])
    rating = IntegerField('Rating', validators=[DataRequired()])
    submit = SubmitField('Submit')


# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


# Login form
class LoginForm(FlaskForm):
    username_or_email = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')


def admin_required():
    if not current_user.is_authenticated or not current_user.is_admin:
        flash('You must be an admin to view this page.')
        return redirect(url_for('login'))

with app.app_context():
    db.create_all()

@app.template_filter('float')
def float_filter(value):
    return float(value)

@app.context_processor
def inject_username():
    if current_user.is_authenticated:
        return {'username': current_user.username}
    else:
        return {'username': None}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/change_language', methods=['POST'])
def change_language():
    language_code = request.form.get('language_code')
    response = make_response({"message": "Language changed successfully"})
    response.set_cookie('language', language_code)
    return response

@app.route('/')
def home():
    target_language = request.cookies.get('language', default='en')  # Get the language from a cookie
    latest_products = Product.query.filter_by(latest_product=True).all()
    popular_products = Product.query.filter_by(popular_product=True).all()

    # Translate the name and description of each product
    for product in latest_products:
        product.name = translate_text(product.name, target_language)
        product.description = translate_text(product.description, target_language)
    for product in popular_products:
        product.name = translate_text(product.name, target_language)
        product.description = translate_text(product.description, target_language)
    latest_trans = translate_text('Latest Product', target_language)
    popular_trans = translate_text('Popular Products', target_language)

    return render_template('home.html', latest_products=latest_products, popular_products=popular_products, latest_trans=latest_trans, popular_trans=popular_trans)

@app.route('/contact')
def contact():
    return render_template('contactus.html')

@app.route('/contact-success')
def contact_success():
    return render_template('contact-success.html')


@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def view_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = CommentForm()

    existing_comment = None
    user_commented = False
    user_rated = False

    # Check if the user is logged in and has already commented or rated the product
    if current_user.is_authenticated:
        existing_comment = Comment.query.filter_by(
            username=current_user.username,
            product_id=product.id
        ).first()

        user_commented = existing_comment is not None
        user_rated = existing_comment is not None and existing_comment.rating is not None

    if form.validate_on_submit():
        if current_user.is_authenticated:
            if not user_commented and not user_rated:
                rating = form.rating.data
                if rating is not None:
                    rating = int(rating)
                    comment = Comment(
                        username=current_user.username,
                        product_id=product.id,
                        comment=form.comment.data,
                        rating=rating,
                        date=datetime.now().replace(microsecond=0)  # Remove the decimal seconds
                    )

                    # Update the product's rating and number of ratings
                    product.num_ratings += 1
                    product.rating = (
                        (product.rating * (product.num_ratings - 1)) + rating
                    ) / product.num_ratings

                    db.session.add(comment)
                    db.session.commit()
                    flash('Comment and rating added successfully!', 'success')
                    return redirect(url_for('view_product', product_id=product.id))

                else:
                    flash('Invalid rating value.', 'error')
            else:
                flash('You have already submitted a comment and/or rating for this product.', 'warning')
        else:
            flash('You need to login to submit a comment or rating.', 'warning')

    return render_template('product.html', product=product, form=form, user_commented=user_commented, user_rated=user_rated)

@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Ensure the user is the author of the comment
    if comment.username != current_user.username:
        abort(403)

    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        # Save the old rating
        old_rating = comment.rating

        # Update the comment and rating
        comment.comment = comment_form.comment.data
        comment.rating = int(comment_form.rating.data)

        # Get the product associated with this comment
        product = Product.query.get(comment.product_id)

        # Calculate total sum of ratings excluding this one
        total_rating_excluding_this = product.rating * product.num_ratings - old_rating

        # Add the new rating to the total, then divide by the number of ratings
        product.rating = (total_rating_excluding_this + comment.rating) / product.num_ratings
        
        db.session.commit()

        flash('Your comment and rating have been updated!', 'success')
        return redirect(url_for('view_product', product_id=comment.product_id))
    elif request.method == 'GET':
        # Pre-fill the form fields with the current comment and rating
        comment_form.comment.data = comment.comment
        comment_form.rating.data = comment.rating

    return render_template('edit_comment.html', comment_form=comment_form)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Ensure the user is the author of the comment
    if comment.username != current_user.username:
        abort(403)
    
    # Get the product associated with this comment
    product = Product.query.get(comment.product_id)

    # Update the product's rating
    if product.num_ratings > 1:
        # If there are other ratings, recalculate the average excluding this comment's rating
        product.rating = ((product.rating * product.num_ratings) - comment.rating) / (product.num_ratings - 1)
        product.num_ratings -= 1
    else:
        # If this is the only rating, set product rating to None or 0 (depending on your design)
        product.rating = 0

    db.session.delete(comment)
    db.session.commit()
    flash('Your comment has been deleted!', 'success')
    return redirect(url_for('view_product', product_id=comment.product_id))

@app.route('/base')
def base():
    return render_template('base.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    admin_required()
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        description = request.form['description']
        latest_product = 'latest_product' in request.form
        popular_product = 'popular_product' in request.form
        category_input = request.form['category']

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

        # Check if the category already exists
        category = Categories.query.filter_by(name=category_input).first()

        # If it doesn't exist, create it
        if category is None:
            category = Categories(name=category_input)
            db.session.add(category)
            db.session.commit()  # Make sure to commit so the category is saved

        # Assign the existing or new category to the product
        if category is not None:
            product.category = category.name

        db.session.add(product)
        db.session.commit()

        return redirect(url_for('admin'))

    products = Product.query.all()
    return render_template('admin.html', products=products)

    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/admin/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    admin_required()
    product = Product.query.get_or_404(product_id)
    if product.image_path:
        os.remove(os.path.join(app.static_folder, product.image_path))
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/admin/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    admin_required()
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

@app.route('/store', methods=['GET'])
def store():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 9, type=int)  # Define items per page as you wish
    search_query = request.args.get('search_query', '')
    category = request.args.get('category', '')
    sort_by = request.args.get('sort_by', '')

    # Modify your filter_products function to return a query instead of list of products
    query = filter_products(search_query, category, sort_by)

    # Add pagination to your query
    paginated_products = query.paginate(page=page, per_page=per_page, error_out=False)

    categories = Categories.query.all()
    return render_template('store.html', products=paginated_products, categories=categories, sort_by=sort_by)

def filter_products(search_query, category, sort_by):
    query = Product.query

    if search_query:
        query = query.filter(Product.name.ilike(f'%{search_query}%'))

    if category:
        query = query.filter(Product.category == str(category))  # Make sure this line is correctly filtering by category

    if sort_by == 'rating':
        query = query.order_by(desc(Product.rating))
    
    if sort_by == 'price desc':
        query = query.order_by(desc(Product.price))

    # Just return the query object, not the executed query
    return query

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
        if username.lower() == 'admin':
            user.is_admin = True
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect('/login')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        input = form.username_or_email.data
        password = form.password.data

        # Check if the input exists as a username or email in the database
        user = User.query.filter((User.username == input) | (User.email == input)).first()
        if not user or not user.check_password(password):
            flash('Invalid username/email or password. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        login_user(user)  # This is the proper way to log in a user

        flash('Logged in successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    # Clear the session data
    session.clear()
    # Redirect to the home page or any other page after logout
    return redirect(url_for('home'))

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    product_id = str(product_id)
    if 'shoppingcart' not in session:
        session['shoppingcart'] = {}

    product = Product.query.get(int(product_id))
    if product:
        if product_id in session['shoppingcart']:
            session['shoppingcart'][product_id]['quantity'] += 1
        else:
            session['shoppingcart'][product_id] = {
                'name': product.name,
                'price': str(product.price),
                'quantity': 1
            }
    session.modified = True
    return redirect(url_for('shoppingcart'))

@app.route('/shoppingcart')
def shoppingcart():
    total_price = 0
    for item in session.get('shoppingcart', {}).values():
        total_price += float(item['price']) * item['quantity']
    return render_template('shoppingcart.html', shoppingcart=session.get('shoppingcart', {}), total_price=total_price)

@app.route('/deletefromcart/<int:product_id>')
def deletefromcart(product_id):
    product_id = str(product_id)
    if 'shoppingcart' in session and product_id in session['shoppingcart']:
        del session['shoppingcart'][product_id]
    session.modified = True
    return redirect(url_for('shoppingcart'))

@app.route('/updatecart/<int:product_id>', methods=['POST'])
def updatecart(product_id):
    product_id = str(product_id)
    quantity = request.form.get('quantity')
    if quantity is not None and int(quantity) > 0 and 'shoppingcart' in session and product_id in session['shoppingcart']:
        session['shoppingcart'][product_id]['quantity'] = int(quantity)
    session.modified = True
    return redirect(url_for('shoppingcart'))

@app.route('/payment', methods=['GET'])
def payment():
    # Render payment form page
    # Fetch cart contents from the session
    cart_contents = list(session.get('shoppingcart', {}).values())
    total_price = sum(float(item['price']) * int(item['quantity']) for item in cart_contents)

    return render_template('payment.html', products=cart_contents, total_price=total_price)

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/support_submitted')
def support_submitted():
    return render_template('support_submitted.html')

@app.route('/clear_cart', methods=['POST'])
def clear_cart():
    session['shoppingcart'] = {}
    return redirect(url_for('store'))

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json  # Get JSON data from the request
    message = data.get('message', '')  # Extract the 'message' value from the JSON
    response = generate_response(message)  # Generate a response using the function defined above
    return jsonify({'response': response})  # Return the response as JSON

@app.route('/chatbot')
def chatbot():
    return render_template('chatbot.html')

if __name__ == '__main__':
    db.create_all()
    app.run(debug=False, host='0.0.0.0')