import os

from cs50 import SQL
from flask import Flask, redirect, render_template, request, session, flash
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helper_func import login_required

# Configure application
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")

# Copied From CS50 Finance
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Logs the user in
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Please enter your username.", "warning")
            return render_template("/login")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Please enter your password.", "warning")
            return render_template("/login")

        else:
            # Query database for username
            rows = db.execute(
                "SELECT * FROM users WHERE username = ?", request.form.get("username")
            )

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(
                rows[0]["hashed_password"], request.form.get("password")
            ):
                flash("Invalid username and/or password", "danger")
                return render_template("login.html")

            # Remember which user has logged in
            session["user_id"] = rows[0]["id"]

            # Flash successful login message
            flash("Logged in successfully!", "success")

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


# Logs the user out
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Flash logout message
    flash("You have been logged out.", "info")

    # Redirect user to login form
    return redirect("/")


# Registers the user
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Please enter a username.", "warning")
            return render_template("register.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Please enter a password.", "warning")
            return render_template("register.html")

        # Ensure the password entered on both fields is correct
        elif request.form.get("password") != request.form.get("confirmation"):
            flash("Passwords do not match", "danger")
            return render_template("register.html")

        # Check if username already in database
        same_username = db.execute("SELECT * FROM users WHERE username = ?",
                                   request.form.get("username"))
        if len(same_username) > 0:
            flash("Username already taken", "danger")
            return render_template("register.html")

        # Hash the password
        hashed_password = generate_password_hash(request.form.get("password"))

        # Store username and hashed password into the database
        username = request.form.get("username")
        db.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)",
                   username, hashed_password)

        # Query the database again to get the new user's id
        rows = db.execute("SELECT id FROM users WHERE username = ?", username)

        # Ensure the user is inserted and retrieve the id
        if len(rows) != 1:
            flash("Registration failed, try again.", "danger")
            return render_template("register.html")

        # Log the user in by storing the user_id in the session
        session["user_id"] = rows[0]["id"]

        # Flash success message
        flash("Registration successful! You are now logged in.", "success")

        # Redirect to the home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


# Homepage
@app.route("/")
@login_required
def index():
    user_id = session["user_id"]

    # Query the database for the user's BMI history
    bmi_records = db.execute(
        "SELECT bmi_value, date FROM bmi_records WHERE user_id = ? ORDER BY date ASC",
        user_id
    )
    bmi_dates = [record['date'] for record in bmi_records]
    bmi_values = [record['bmi_value'] for record in bmi_records]

    # Query the database for the user's sleep history
    sleep_records = db.execute(
        "SELECT sleep_hours, sleep_quality, date FROM sleep_records WHERE user_id = ? ORDER BY date DESC",
        user_id
    )
    sleep_dates = [record['date'] for record in sleep_records]
    sleep_hours = [record['sleep_hours'] for record in sleep_records]
    sleep_quality = [record['sleep_quality'] for record in sleep_records]  # Capture sleep quality

    # Query the database for the user's exercise history
    exercise_records = db.execute(
        "SELECT exercise_name, reps, sets, date, targeted_part FROM exercise_records WHERE user_id = ? ORDER BY date DESC",
        user_id
    )

    # Query the database for the user's macro intake history
    macro_records = db.execute(
        "SELECT food_name, meal_type, protein, carbohydrates, fats, calories, date FROM macro_records WHERE user_id = ? ORDER BY date DESC",
        user_id
    )

    return render_template("index.html",
                           bmi_dates=bmi_dates,
                           bmi_values=bmi_values,
                           sleep_dates=sleep_dates,
                           sleep_hours=sleep_hours,
                           sleep_quality=sleep_quality,
                           exercise_records=exercise_records,
                           macro_records=macro_records
                           )


# BMI calculator
@app.route("/bmi", methods=["GET", "POST"])
@login_required
def bmi():
    if request.method == "POST":
        # Get form data
        mass = float(request.form.get("mass"))
        height_cm = float(request.form.get("height"))
        age = int(request.form.get("age"))  # Age is collected but not used in this calculation

        # Convert height from cm to meters
        height_m = height_cm / 100

        # Calculate BMI
        bmi_value = mass / (height_m ** 2)
        bmi_value = round(bmi_value, 2)  # Round BMI to two decimal places

        # Determine BMI category
        if bmi_value < 18.5:
            classification = "Underweight"
        elif 18.5 <= bmi_value < 24.9:
            classification = "Normal weight"
        elif 25 <= bmi_value < 29.9:
            classification = "Overweight"
        else:
            classification = "Obese"

        # Store the BMI in the database
        user_id = session["user_id"]
        db.execute("INSERT INTO bmi_records (user_id, bmi_value, classification) VALUES (?, ?, ?)",
                   user_id, bmi_value, classification)

        # Render the template with the calculated BMI and classification
        return render_template("bmi.html", bmi=bmi_value, classification=classification)

    # For GET request, just render the form
    return render_template("bmi.html")


# Exercise Tracker
@app.route("/exercise", methods=["GET", "POST"])
@login_required
def exercise():
    user_id = session["user_id"]

    if request.method == "POST":
        # Get form data
        exercise_name = request.form.get("exercise_name")
        targeted_part = request.form.get("targeted_part")
        reps = request.form.get("reps")
        sets = request.form.get("sets")
        duration = request.form.get("duration")

        # Insert the exercise record into the database
        db.execute("INSERT INTO exercise_records (user_id, exercise_name, targeted_part, reps, sets, duration) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, exercise_name, targeted_part, reps, sets, duration)

        # Flash success message
        flash("Exercise logged successfully!", "success")

        # Redirect to the exercise page to prevent form resubmission
        return redirect("/exercise")

    # For GET request, query the database for the user's exercise history
    exercise_records = db.execute(
        "SELECT exercise_name, targeted_part, reps, sets, duration, date FROM exercise_records WHERE user_id = ? ORDER BY date DESC", user_id)

    return render_template("exercise.html", records=exercise_records)


# Macro Tracker
@app.route("/macro", methods=["GET", "POST"])
@login_required
def macro():
    if request.method == "POST":
        # Get form data
        protein = request.form.get("protein")
        carbohydrates = request.form.get("carbohydrates")
        fats = request.form.get("fats")
        calories = request.form.get("calories")
        meal_type = request.form.get("meal_type")
        food_name = request.form.get("food_name")
        intake_time = request.form.get("intake_time")

        # Log the macro in the database
        user_id = session["user_id"]
        db.execute("INSERT INTO macro_records (user_id, protein, carbohydrates, fats, calories, meal_type, food_name, intake_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ",
                   user_id, protein, carbohydrates, fats, calories, meal_type, food_name, intake_time)

        flash("Macros logged successfully!", "success")
        return redirect("/macro")

    # For GET request, query the database for the user's macro history
    user_id = session["user_id"]
    macro_records = db.execute(
        "SELECT protein, carbohydrates, fats, calories, meal_type, food_name, date FROM macro_records WHERE user_id = ? ORDER BY date DESC", user_id)

    return render_template("macro.html", macro_records=macro_records)


# Sleep Tracker
@app.route("/sleep", methods=["GET", "POST"])
@login_required
def sleep():
    user_id = session["user_id"]

    if request.method == "POST":
        # Get form data
        try:
            sleep_hours = float(request.form.get("sleep_hours"))
            sleep_quality = request.form.get("sleep_quality")
            sleep_date = request.form.get("date")

            # Validate sleep hours
            if sleep_hours < 0:
                flash("Sleep hours must be a positive number!", "danger")
                return redirect("/sleep")

            # Insert the sleep record into the database
            db.execute("INSERT INTO sleep_records (user_id, sleep_hours, sleep_quality, date) VALUES (?, ?, ?, ?)",
                       user_id, sleep_hours, sleep_quality, sleep_date)

            # Flash success message
            flash("Sleep record logged successfully!", "success")

        except Exception as e:
            flash(f"Error logging sleep record: {str(e)}", "danger")

        # Redirect to avoid form resubmission
        return redirect("/sleep")

    # For GET request, query the database for the user's sleep history
    sleep_records = db.execute(
        "SELECT sleep_hours, sleep_quality, date FROM sleep_records WHERE user_id = ? ORDER BY date DESC", user_id)

    return render_template("sleep.html", sleep_records=sleep_records)


# Profile
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session["user_id"]

    # Fetch the user's current information
    user_info = db.execute("SELECT username FROM users WHERE id = ?", user_id)
    if not user_info:
        flash("User not found.", "danger")
        return redirect("/")

    username = user_info[0]["username"]

    # Calculate the latest BMI
    latest_bmi_data = db.execute(
        "SELECT bmi_value FROM bmi_records WHERE user_id = ? ORDER BY date DESC LIMIT 1", user_id)

    latest_bmi = latest_bmi_data[0]["bmi_value"] if latest_bmi_data else None
    latest_bmi = round(latest_bmi, 2) if latest_bmi else None

    # Calculate average calories intake
    average_calories_data = db.execute(
        "SELECT AVG(calories) AS avg_calories FROM macro_records WHERE user_id = ?", user_id)

    average_calories = average_calories_data[0]["avg_calories"] if average_calories_data and average_calories_data[0]["avg_calories"] is not None else 0
    average_calories = round(average_calories, 1)

    # Calculate average hours of sleep
    average_sleep_data = db.execute(
        "SELECT AVG(sleep_hours) AS avg_sleep FROM sleep_records WHERE user_id = ?", user_id)

    average_sleep = average_sleep_data[0]["avg_sleep"] if average_sleep_data and average_sleep_data[0]["avg_sleep"] is not None else 0
    average_sleep = round(average_sleep, 2)

    if request.method == "POST":
        # Handle change username
        if request.form.get("change_username"):
            new_username = request.form.get("new_username")

            # Check if username was provided
            if not new_username:
                flash("Please provide a new username.", "warning")
                return render_template("profile.html", username=username,
                                       latest_bmi=latest_bmi,
                                       average_calories=average_calories,
                                       average_sleep=average_sleep)

            # Check if the new username already exists in the database
            existing_user = db.execute("SELECT * FROM users WHERE username = ?", new_username)
            if existing_user:
                flash("Username is already taken, choose another one.", "danger")
                return render_template("profile.html", username=username,
                                       latest_bmi=latest_bmi,
                                       average_calories=average_calories,
                                       average_sleep=average_sleep)

            # Update username in the database
            db.execute("UPDATE users SET username = ? WHERE id = ?", new_username, user_id)
            flash("Username updated successfully!", "success")
            return redirect("/profile")

        # Handle password change
        if request.form.get("current_password"):
            current_password = request.form.get("current_password")
            new_password = request.form.get("new_password")
            confirmation = request.form.get("confirmation")

            # Validate password change inputs
            if not current_password or not new_password:
                flash("Please provide both the current and new passwords.", "warning")
                return render_template("profile.html", username=username,
                                       latest_bmi=latest_bmi,
                                       average_calories=average_calories,
                                       average_sleep=average_sleep)

            if new_password != confirmation:
                flash("New passwords do not match.", "danger")
                return render_template("profile.html", username=username,
                                       latest_bmi=latest_bmi,
                                       average_calories=average_calories,
                                       average_sleep=average_sleep)

            # Verify current password
            user = db.execute("SELECT hashed_password FROM users WHERE id = ?", user_id)
            if not user or not check_password_hash(user[0]["hashed_password"], current_password):
                flash("Current password is incorrect.", "danger")
                return render_template("profile.html", username=username,
                                       latest_bmi=latest_bmi,
                                       average_calories=average_calories,
                                       average_sleep=average_sleep)

            # Hash and update the new password
            hashed_new_password = generate_password_hash(new_password)
            db.execute("UPDATE users SET hashed_password = ? WHERE id = ?",
                       hashed_new_password, user_id)

            flash("Password updated successfully!", "success")
            return redirect("/profile")

    # Render the profile page with the username and calculated values
    return render_template("profile.html", username=username,
                           latest_bmi=latest_bmi,
                           average_calories=average_calories,
                           average_sleep=average_sleep)


# Privacy PO
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')
