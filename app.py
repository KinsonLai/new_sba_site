from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    make_response,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    current_user,
    LoginManager,
    login_required,
    login_user,
    UserMixin,
)
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

nltk.download("punkt")
nltk.download("stopwords")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static/upload_products")
app.config["SESSION_COOKIE_PATH"] = "/"
app.secret_key = "aSecrETkEy"
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)

synonyms = {
    "founder": ["creator", "owner", "founder"],
    "sell": ["offer", "sell", "have", "stock", "supply", "product"],
    "payment": ["payment", "pay", "credit", "transaction"],
    "delivery": ["shipping", "delivery", "dispatch", "mail"],
    "fee": ["charge", "cost", "fee", "price"],
    "greeting": ["hi", "hello", "hey"],
    "thanks": ["thank", "thanks", "appreciate", "grateful"],
    "farewell": ["bye", "goodbye", "see you"],
}


def generate_response(message):
    words = word_tokenize(message.lower())

    words = [
        word
        for word in words
        if word not in stopwords.words("english") and word not in string.punctuation
    ]

    for word in words:
        if word in synonyms["founder"]:
            return "Our shop was founded by Jaygo."
        elif word in synonyms["sell"]:
            return "We sell computers and electronic gadgets."
        elif word in synonyms["payment"]:
            return "You can pay using credit card, Alipay, or Octopus Card."
        elif word in synonyms["delivery"]:
            return "Your order will be delivered in 3 business days."
        elif word in synonyms["fee"]:
            return "No delivery fee is needed, shipping is free!"
        elif word in synonyms["greeting"]:
            return "Hello! How can I assist you today?"
        elif word in synonyms["thanks"]:
            return (
                "You're welcome! Let us know if there's anything else we can help with."
            )
        elif word in synonyms["farewell"]:
            return "Goodbye! Have a great day!"

    return "Sorry, I'm not sure how to answer that. Can you ask something else?"


def translate_text(text, target_language):
    translator = Translator()
    result = translator.translate(text, dest=target_language)
    language_code_map = {
        "en": "en",
        "fr": "fr",
        "ja": "ja",
    }
    googletrans_language = language_code_map.get(target_language)
    if googletrans_language is None:
        raise ValueError(f"Invalid language code: {target_language}")
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
    comments = db.relationship("Comment", backref="product", lazy=True)
    category = db.Column(db.String(100), nullable=False)


class Categories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class CommentForm(FlaskForm):
    comment = TextAreaField("Comment", validators=[DataRequired()])
    rating = IntegerField("Rating", validators=[DataRequired()])
    submit = SubmitField("Submit")


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Sign Up")


class LoginForm(FlaskForm):
    username_or_email = StringField("Username or Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Login")


def admin_required():
    if not current_user.is_authenticated or not current_user.is_admin:
        flash("You must be an admin to view this page.")
        return redirect(url_for("login"))


with app.app_context():
    db.create_all()


@app.template_filter("float")
def float_filter(value):
    return float(value)


@app.context_processor
def inject_username():
    if current_user.is_authenticated:
        return {"username": current_user.username}
    else:
        return {"username": None}


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/change_language", methods=["POST"])
def change_language():
    language_code = request.form.get("language_code")
    response = make_response({"message": "Language changed successfully"})
    response.set_cookie("language", language_code)
    return response


@app.route("/")
def home():
    target_language = request.cookies.get("language", default="en")
    latest_products = Product.query.filter_by(latest_product=True).all()
    popular_products = Product.query.filter_by(popular_product=True).all()

    for product in latest_products:
        product.name = translate_text(product.name, target_language)
        product.description = translate_text(product.description, target_language)
    for product in popular_products:
        product.name = translate_text(product.name, target_language)
        product.description = translate_text(product.description, target_language)
    latest_trans = translate_text("Latest Product", target_language)
    popular_trans = translate_text("Popular Products", target_language)

    return render_template(
        "home.html",
        latest_products=latest_products,
        popular_products=popular_products,
        latest_trans=latest_trans,
        popular_trans=popular_trans,
    )


@app.route("/contact")
def contact():
    return render_template("contactus.html")


@app.route("/contact-success")
def contact_success():
    return render_template("contact-success.html")


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def view_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = CommentForm()

    existing_comment = None
    user_commented = False
    user_rated = False

    if current_user.is_authenticated:
        existing_comment = Comment.query.filter_by(
            username=current_user.username, product_id=product.id
        ).first()

        user_commented = existing_comment is not None
        user_rated = (
            existing_comment is not None and existing_comment.rating is not None
        )

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
                        date=datetime.now().replace(microsecond=0),
                    )

                    product.num_ratings += 1
                    product.rating = (
                        (product.rating * (product.num_ratings - 1)) + rating
                    ) / product.num_ratings

                    db.session.add(comment)
                    db.session.commit()
                    flash("Comment and rating added successfully!", "success")
                    return redirect(url_for("view_product", product_id=product.id))

                else:
                    flash("Invalid rating value.", "error")
            else:
                flash(
                    "You have already submitted a comment and/or rating for this product.",
                    "warning",
                )
        else:
            flash("You need to login to submit a comment or rating.", "warning")

    return render_template(
        "product.html",
        product=product,
        form=form,
        user_commented=user_commented,
        user_rated=user_rated,
    )


@app.route("/edit_comment/<int:comment_id>", methods=["GET", "POST"])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if comment.username != current_user.username:
        abort(403)

    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        old_rating = comment.rating

        comment.comment = comment_form.comment.data
        comment.rating = int(comment_form.rating.data)

        product = Product.query.get(comment.product_id)

        total_rating_excluding_this = product.rating * product.num_ratings - old_rating

        product.rating = (
            total_rating_excluding_this + comment.rating
        ) / product.num_ratings

        db.session.commit()

        flash("Your comment and rating have been updated!", "success")
        return redirect(url_for("view_product", product_id=comment.product_id))
    elif request.method == "GET":
        comment_form.comment.data = comment.comment
        comment_form.rating.data = comment.rating

    return render_template("edit_comment.html", comment_form=comment_form)


@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if comment.username != current_user.username:
        abort(403)

    product = Product.query.get(comment.product_id)

    if product.num_ratings > 1:
        product.rating = ((product.rating * product.num_ratings) - comment.rating) / (
            product.num_ratings - 1
        )
        product.num_ratings -= 1
    else:
        product.rating = 0

    db.session.delete(comment)
    db.session.commit()
    flash("Your comment has been deleted!", "success")
    return redirect(url_for("view_product", product_id=comment.product_id))


@app.route("/base")
def base():
    return render_template("base.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/admin", methods=["GET", "POST"])
def admin():
    admin_required()
    if request.method == "POST":
        name = request.form["name"]
        price = float(request.form["price"])
        description = request.form["description"]
        latest_product = "latest_product" in request.form
        popular_product = "popular_product" in request.form
        category_input = request.form["category"]

        image = request.files["image"]
        if image:
            filename = secure_filename(image.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename
            image_path = os.path.join("upload_products/", unique_filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_filename))
        else:
            image_path = None

        product = Product(
            name=name,
            price=price,
            image_path=image_path,
            description=description,
            latest_product=latest_product,
            popular_product=popular_product,
        )

        category = Categories.query.filter_by(name=category_input).first()

        if category is None:
            category = Categories(name=category_input)
            db.session.add(category)
            db.session.commit()

        if category is not None:
            product.category = category.name

        db.session.add(product)
        db.session.commit()

        return redirect(url_for("admin"))

    products = Product.query.all()
    return render_template("admin.html", products=products)

    products = Product.query.all()
    return render_template("admin.html", products=products)


@app.route("/admin/delete/<int:product_id>", methods=["POST"])
def delete_product(product_id):
    admin_required()
    product = Product.query.get_or_404(product_id)
    if product.image_path:
        os.remove(os.path.join(app.static_folder, product.image_path))
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for("admin"))


@app.route("/admin/edit/<int:product_id>", methods=["GET", "POST"])
def edit_product(product_id):
    admin_required()
    product = Product.query.get_or_404(product_id)

    if request.method == "POST":
        product.name = request.form["name"]
        product.price = float(request.form["price"])
        product.rating = float(request.form["rating"])
        product.comment = request.form["comment"]
        product.description = request.form["description"]
        product.latest_product = "latest_product" in request.form
        product.popular_product = "popular_product" in request.form

        image = request.files["image"]
        if image:
            if product.image_path:
                os.remove(os.path.join(app.static_folder, product.image_path))
            filename = secure_filename(image.filename)
            unique_filename = str(uuid.uuid4()) + "_" + filename
            image_path = os.path.join("upload_products", unique_filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_filename))
            product.image_path = image_path

        db.session.commit()
        return redirect(url_for("admin"))

    return render_template("edit_product.html", product=product)


@app.route("/store", methods=["GET"])
def store():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 9, type=int)
    search_query = request.args.get("search_query", "")
    category = request.args.get("category", "")
    sort_by = request.args.get("sort_by", "")

    query = filter_products(search_query, category, sort_by)

    paginated_products = query.paginate(page=page, per_page=per_page, error_out=False)

    categories = Categories.query.all()
    return render_template(
        "store.html",
        products=paginated_products,
        categories=categories,
        sort_by=sort_by,
    )


def filter_products(search_query, category, sort_by):
    query = Product.query

    if search_query:
        query = query.filter(Product.name.ilike(f"%{search_query}%"))

    if category:
        query = query.filter(Product.category == str(category))

    if sort_by == "rating":
        query = query.order_by(desc(Product.rating))

    if sort_by == "price desc":
        query = query.order_by(desc(Product.price))

    return query


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        existing_user = (
            User.query.filter_by(username=username).first()
            or User.query.filter_by(email=email).first()
        )
        if existing_user:
            flash(
                "Username or email already exists. Please choose a different one.",
                "danger",
            )
            return redirect("/register")

        user = User(username=username, email=email, password=password)
        if username.lower() == "admin":
            user.is_admin = True
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect("/login")

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        input = form.username_or_email.data
        password = form.password.data

        user = User.query.filter(
            (User.username == input) | (User.email == input)
        ).first()
        if not user or not user.check_password(password):
            flash("Invalid username/email or password. Please try again.", "danger")
            return redirect(url_for("login"))

        login_user(user)

        flash("Logged in successfully!", "success")
        return redirect(url_for("home"))

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    session.clear()

    return redirect(url_for("home"))


@app.route("/add_to_cart/<int:product_id>")
def add_to_cart(product_id):
    product_id = str(product_id)
    if "shoppingcart" not in session:
        session["shoppingcart"] = {}

    product = Product.query.get(int(product_id))
    if product:
        if product_id in session["shoppingcart"]:
            session["shoppingcart"][product_id]["quantity"] += 1
        else:
            session["shoppingcart"][product_id] = {
                "name": product.name,
                "price": str(product.price),
                "quantity": 1,
            }
    session.modified = True
    return redirect(url_for("shoppingcart"))


@app.route("/shoppingcart")
def shoppingcart():
    total_price = 0
    for item in session.get("shoppingcart", {}).values():
        total_price += float(item["price"]) * item["quantity"]
    return render_template(
        "shoppingcart.html",
        shoppingcart=session.get("shoppingcart", {}),
        total_price=total_price,
    )


@app.route("/deletefromcart/<int:product_id>")
def deletefromcart(product_id):
    product_id = str(product_id)
    if "shoppingcart" in session and product_id in session["shoppingcart"]:
        del session["shoppingcart"][product_id]
    session.modified = True
    return redirect(url_for("shoppingcart"))


@app.route("/updatecart/<int:product_id>", methods=["POST"])
def updatecart(product_id):
    product_id = str(product_id)
    quantity = request.form.get("quantity")
    if (
        quantity is not None
        and int(quantity) > 0
        and "shoppingcart" in session
        and product_id in session["shoppingcart"]
    ):
        session["shoppingcart"][product_id]["quantity"] = int(quantity)
    session.modified = True
    return redirect(url_for("shoppingcart"))


@app.route("/payment", methods=["GET"])
def payment():
    cart_contents = list(session.get("shoppingcart", {}).values())
    total_price = sum(
        float(item["price"]) * int(item["quantity"]) for item in cart_contents
    )

    return render_template(
        "payment.html", products=cart_contents, total_price=total_price
    )


@app.route("/success")
def success():
    tracking_number = str(uuid.uuid4())
    return render_template("success.html", tracking_number=tracking_number)


@app.route("/support")
def support():
    return render_template("support.html")


@app.route("/support_submitted")
def support_submitted():
    return render_template("support_submitted.html")


@app.route("/clear_cart", methods=["POST"])
def clear_cart():
    session["shoppingcart"] = {}
    return redirect(url_for("store"))


@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    message = data.get("message", "")
    response = generate_response(message)
    return jsonify({"response": response})


@app.route("/chatbot")
def chatbot():
    return render_template("chatbot.html")


if __name__ == "__main__":
    db.create_all()
    app.run(debug=False, host="0.0.0.0")
