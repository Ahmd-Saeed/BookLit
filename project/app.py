import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session

from helpers import apology
from werkzeug.security import check_password_hash, generate_password_hash
import secrets


# Configure application
app = Flask(__name__)

app.secret_key = secrets.token_hex(16)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///booklit.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response




@app.route("/", methods=["GET", "POST"])
def index():
     if request.method == "GET":
        return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        booknum = db.execute("SELECT books FROM users WHERE id = ?", session["user_id"])
        books = db.execute("SELECT * FROM books WHERE user_id=?", session["user_id"])
        # Redirect user to home page
        return render_template("main.html", username = request.form.get("username"), booknum = booknum, books = books)
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.form.get("password") != request.form.get("confirmation"):
        return apology("Password and confirmation don't match")

    if not request.form.get("username"):
        return apology("must provide username")
    if not request.form.get("password"):
        return apology("must provide password")
    if not request.form.get("confirmation"):
        return apology("must provide password confirmation")

    username =  request.form.get("username")
    password = request.form.get("password")
    hashPassword = generate_password_hash(password)

    if not db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username")):
        newUser = db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", username, hashPassword)
        rows = db.execute("SELECT id FROM users WHERE username =  ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]
    else:
        return apology("Username already in use")

    return redirect("/login")



@app.route("/main", methods=["GET", "POST"])
def main():
       username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
       username = username[0]["username"]
       booknum = db.execute("SELECT books FROM users WHERE id = ?", session["user_id"])
       books = db.execute("SELECT * FROM books WHERE user_id=?", session["user_id"])

       return render_template("main.html", username = username, booknum = booknum, books = books)



@app.route("/add", methods=["GET", "POST"])
def add():
    if request.method == "GET":
        return render_template("add.html")
    if request.method == "POST":
        bookName = request.form.get("bookName")
        author = request.form.get("author")
        genre = request.form.get("genre")
        fullpages = request.form.get("fullpages")
        readpages = request.form.get("readpages")
        newBook = db.execute("INSERT INTO books(user_id, name, author, genre, fullpages, readpages) VALUES (?,?,?,?,?,?)", session["user_id"], bookName, author, genre, fullpages, readpages)
        incrementBooks = db.execute("UPDATE users SET books = books + 1 WHERE id = ?", session["user_id"])
    return redirect("/main")



@app.route("/remove", methods=["GET", "POST"])
def remove():
    if request.method == "GET":
         currentBooks = db.execute("SELECT name FROM books WHERE user_id = ?", session["user_id"])
         return render_template("remove.html", currentBooks = currentBooks)
    if request.method == "POST":
        bookName = request.form.get("bookName")
        RemoveBook = db.execute("DELETE FROM books WHERE name = ? ", bookName)
        DecrementBooks = db.execute("UPDATE users SET books = books - 1 WHERE id = ?", session["user_id"])
    return redirect("/main")

@app.route("/update", methods=["GET", "POST"])
def update():
    if request.method == "GET":
         currentBooks = db.execute("SELECT name FROM books WHERE user_id = ?", session["user_id"])
         return render_template("update.html", currentBooks = currentBooks)
    if request.method == "POST":
        bookName = request.form.get("bookName")
        readPages = request.form.get("readpages")
        updatePages = db.execute("UPDATE books SET readpages = ? WHERE user_id = ? AND name = ?", readPages, session["user_id"], bookName)
    return redirect("/main")


@app.route("/fav", methods=["GET", "POST"])
def favorite():
    setToFavorite = db.execute("UPDATE books SET favorite = ? WHERE user_id = ?", "yes", session["user_id"])
    return redirect("/main")
