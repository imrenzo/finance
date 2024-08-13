import os
import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


def time_now(now):
    year = now.year
    month = now.month
    day = now.day
    hour = now.hour
    minute = now.minute
    second = now.second
    return f"{year}-{month}-{day} {hour}:{minute}:{second}"


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    cash = db.execute("select cash from users where id = ?", session["user_id"])[0]["cash"]
    db.execute("CREATE TABLE stocks1 AS SELECT * FROM stocks where id = ?", session["user_id"])
    db.execute("ALTER TABLE stocks1 DROP COLUMN id")
    shares_dict = db.execute("SELECT * FROM stocks1")[0]
    db.execute("DROP TABLE stocks1")
    shares = []
    total_assets = 0
    for share in shares_dict:
        if shares_dict[share] == 0 or shares_dict[share] is None:
            pass
        else:
            price = (lookup(share))["price"]
            shares.append([share, shares_dict[share], price])
            total_assets += price * shares_dict[share]
    total_assets += cash
    return render_template("index.html", shares=shares, cash=f"{cash:,.2f}", total_assets=f"{total_assets:,.2f}")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        if not request.form.get("symbol"):
            return apology("Blank")
        stock = lookup(request.form.get("symbol"))
        shares = request.form.get("shares")
        if not shares:
            return apology("Please enter qty of shares")
        if shares.isnumeric() is False:
            return apology("Please enter a number in Qty of shares")
        shares = int(shares)
        if stock == None:
            return apology("Invalid symbol")
        if shares <= 0:
            return apology("Qty cannot be negative")
        price = stock["price"]
        symbol = stock["symbol"]
        cash = db.execute("select cash from users where id = ?", session["user_id"])
        cash = cash[0]["cash"]
        total_price = price * shares
        if total_price > cash:
            return apology("Not enough funds")
        # add table if don't have and set value to 0
        try:
            db.execute("alter table stocks add ? INT", symbol)
            db.execute("update stocks set ? = 0", symbol)
        # read current shares_holding and update with new amt
        except RuntimeError:
            pass
        finally:
            query = f"select {symbol} from stocks where id = ?"
            shares_holding = (db.execute(query, session["user_id"]))[0][symbol]
            flash(f"Bought {shares} shares of {symbol} at ${price} each!")
            if shares_holding is None:
                pass
            else:
                shares += shares_holding
            db.execute("update stocks set ? = ? where id = ?", symbol, shares, session["user_id"])
            cash -= total_price
            db.execute("update users set cash = ? where id = ?", cash, session["user_id"])
            time = datetime.datetime.now()
            db.execute("INSERT INTO history (symbol, shares, price, time) VALUES (?, ?, ?, ?)",
                    symbol, shares, price, time_now(time))
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("select * from history")
    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

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

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("password.html")
    else:
        old = request.form.get("old")
        new1 = request.form.get("new1")
        new2 = request.form.get("new2")
        if not old or not new1 or not new2:
            return apology("Please fill in all fields")
        if new1 != new2:
            return apology("New passwords do not match")
        current = db.execute("select hash from users where id = ?", session["user_id"])[0]["hash"]
        if not check_password_hash(current, old):
            return apology("Current password is wrong")
        hash = generate_password_hash(new1)
        db.execute("update users set hash = ? where id = ?", hash, session["user_id"])
        flash("Password changed successfully")
        return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    else:
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return apology("Invalid symbol")
        price = stock["price"]
        symbol = stock["symbol"]
        return render_template("quoted.html", price=f"{price:,.2f}", symbol=symbol)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("Please enter username")
        if not password or not confirmation:
            return apology("Please enter password")
        if password != confirmation:
            return apology("Passwords do not match")
        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (? , ?)", username, hash)
        except ValueError:
            return apology("Username already exists")
        id = (db.execute("SELECT id FROM users WHERE username=?", username))[0]["id"]
        db.execute("insert INTO stocks (id) VALUES (?);", id)
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        db.execute("CREATE TABLE stocks1 AS SELECT * FROM stocks where id = ?", session["user_id"])
        db.execute("ALTER TABLE stocks1 DROP COLUMN id")
        symbols_in_table = db.execute("SELECT * FROM stocks1")[0]
        symbol_holding = []
        print(symbols_in_table["MSFT"])
        for symbol in symbols_in_table:
            if symbols_in_table[symbol] == 0 or symbols_in_table[symbol] is None:
                pass
            else:
                symbol_holding.append(symbol)
        db.execute("DROP TABLE stocks1")
        return render_template("sell.html", symbol_holding=symbol_holding)
    else:
        symbol = (request.form.get("symbol")).upper()
        if not symbol:
            return apology("Please enter a symbol")
        stock = lookup(symbol)
        if stock == None:
            return apology("Invalid symbol")
        shares_to_sell = request.form.get("shares")
        if shares_to_sell.isnumeric() is False:
            return apology("Please enter a number in Qty of shares")
        shares_to_sell = int(shares_to_sell)
        if shares_to_sell <= 0:
            return apology("Qty cannot be negative")
        # access db to see if user owns symbol
        try:
            query = f"select {symbol} from stocks where id = ?"
            shares_holding = db.execute(query, session["user_id"])[0][symbol]
        except RuntimeError:
            return apology("Stock not in portfolio")
        if shares_to_sell > shares_holding:
            return apology("Shares selling exceed holding amount")
        # update db
        cash = db.execute("select cash from users where id = ?", session["user_id"])
        cash = cash[0]["cash"]
        price = (lookup(request.form.get("symbol")))["price"]
        cash += shares_to_sell * price
        db.execute("update users set cash = ? where id = ?", cash, session["user_id"])
        shares_holding -= shares_to_sell
        db.execute("update stocks set ? = ?", symbol, shares_holding)
        time = datetime.datetime.now()
        db.execute("INSERT INTO history (symbol, shares, price, time) VALUES (?, ?, ?, ?)",
                   symbol, -abs(shares_to_sell), price, time_now(time))
        flash(f"Sold {shares_to_sell} shares of {symbol} at ${price} each!")
        return redirect("/")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "GET":
        return apology("GET")
    else:
        try:
            amount = int(request.form.get("amount"))
            cash = db.execute("select cash from users where id = ?", session["user_id"])[0]["cash"]
            cash += amount
            db.execute("update users set cash = ? where id = ?", cash, session["user_id"])
            flash(f"Added ${amount:,.2f} into cash")
            return redirect("/")
        except ValueError:
            return apology("Please enter a number")
