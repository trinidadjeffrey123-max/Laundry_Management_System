from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
from werkzeug.security import check_password_hash
import threading
import webbrowser
import os
from datetime import datetime

app = Flask(__name__)

def open_browser():
    """Opens the web browser to the local Flask application."""
    webbrowser.open_new('http://127.0.0.1:5000/')

# ------------------------------------------------------------
# Flask secret key
# ------------------------------------------------------------
app.secret_key = os.environ.get("SECRET_KEY", "laundry_management_secret_key_2026")


# ------------------------------------------------------------
# MYSQL DATABASE SETTINGS (Environment variable aware)
# ------------------------------------------------------------
MYSQL_HOST = os.environ.get("DB_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("DB_PORT", 3306))
MYSQL_USER = os.environ.get("DB_USER", "root")
MYSQL_PASSWORD = os.environ.get("DB_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("DB_NAME", "laundry_management")


# ------------------------------------------------------------
# DATABASE CONNECTION
# ------------------------------------------------------------
def get_db_connection():
    """Create a connection to the laundry_management database."""
    try:
        connection = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )

        if connection.is_connected():
            return connection

    except Error as error:
        print(f"Database connection error: {error}")

    return None

# ------------------------------------------------------------
# DATABASE HELPERS
# ------------------------------------------------------------
def table_exists(table_name):
    """Check if a table exists in the database."""
    conn = get_db_connection()
    if not conn:
        return False
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = %s AND table_name = %s
            """,
            (MYSQL_DATABASE, table_name)
        )
        return cursor.fetchone()[0] > 0
    except Error:
        return False
    finally:
        cursor.close()
        conn.close()


def get_table_columns(table_name):
    """Return the column names of a table."""
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor()
    try:
        cursor.execute(f"SHOW COLUMNS FROM `{table_name}`")
        return [row[0] for row in cursor.fetchall()]
    except Error:
        return []
    finally:
        cursor.close()
        conn.close()


def find_column(columns, candidates):
    """Find the first matching column name from a list of candidates."""
    for candidate in candidates:
        if candidate in columns:
            return candidate
    return None


# ------------------------------------------------------------
# LOGIN USER HELPERS
# ------------------------------------------------------------
# LOGIN USER HELPERS
# ------------------------------------------------------------
def find_user(login_value, password):
    """
    Find a user in tbl_users.

    This function checks several common column names because the
    exact column structure of tbl_users was not included in the
    database table list.
    """
    if not table_exists("tbl_users"):
        return None, "tbl_users does not exist."

    columns = get_table_columns("tbl_users")

    username_column = find_column(
        columns,
        [
            "username",
            "user_name",
            "email",
            "email_address"
        ]
    )

    password_column = find_column(
        columns,
        [
            "password",
            "password_hash",
            "user_password"
        ]
    )

    status_column = find_column(
        columns,
        [
            "status",
            "user_status",
            "is_active"
        ]
    )

    if not username_column or not password_column:
        return None, (
            "The login columns in tbl_users were not detected. "
            "Make sure tbl_users has username/email and password columns."
        )

    connection = get_db_connection()

    if connection is None:
        return None, "Could not connect to MySQL."

    cursor = connection.cursor(dictionary=True)

    try:
        query = (
            f"SELECT * FROM `tbl_users` "
            f"WHERE `{username_column}` = %s"
        )

        cursor.execute(query, (login_value,))
        user = cursor.fetchone()

        if not user:
            return None, "Invalid username/email or password."

        # Check account status only when a status column exists.
        if status_column:
            status_value = user.get(status_column)

            if str(status_value).lower() in (
                "0",
                "inactive",
                "disabled",
                "false"
            ):
                return None, "This account is inactive."

        stored_password = user.get(password_column)

        if stored_password is None:
            return None, "Password is empty for this account."

        # Support Werkzeug password hashes.
        password_valid = False

        try:
            password_valid = check_password_hash(
                str(stored_password),
                password
            )
        except Exception:
            password_valid = False

        # Also support plain-text passwords for an existing school
        # project database. Hashing is recommended for real systems.
        if not password_valid:
            password_valid = str(stored_password) == str(password)

        if not password_valid:
            return None, "Invalid username/email or password."

        return user, None

    except Error as error:
        print(f"Login query error: {error}")
        return None, "Database error while logging in."

    finally:
        cursor.close()
        connection.close()


# ------------------------------------------------------------
# CREATE ACCOUNT
# ------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    """Display the registration page and process account creation."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        full_name = request.form.get("full_name", "").strip()

        if not username or not password:
            flash("Please enter username and password.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if not table_exists("tbl_users"):
            flash("tbl_users table does not exist.", "error")
            return render_template("register.html")

        connection = get_db_connection()
        if connection is None:
            flash("Could not connect to database.", "error")
            return render_template("register.html")

        cursor = connection.cursor(dictionary=True)
        columns = get_table_columns("tbl_users")

        username_column = find_column(columns, ["username", "user_name", "email", "email_address"])
        password_column = find_column(columns, ["password", "password_hash", "user_password"])
        full_name_column = find_column(columns, ["full_name", "fullname", "name"])
        role_column = find_column(columns, ["role", "user_role", "type"])

        if not username_column or not password_column:
            cursor.close()
            connection.close()
            flash("User table structure not supported.", "error")
            return render_template("register.html")

        # Check if username exists
        cursor.execute(f"SELECT * FROM tbl_users WHERE `{username_column}` = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            connection.close()
            flash("Username already exists.", "error")
            return render_template("register.html")

        try:
            from werkzeug.security import generate_password_hash
            hashed = generate_password_hash(password)

            insert_columns = []
            insert_values = []
            insert_placeholders = []

            insert_columns.append(username_column)
            insert_values.append(username)
            insert_placeholders.append("%s")

            insert_columns.append(password_column)
            insert_values.append(password)
            insert_placeholders.append("%s")

            if full_name_column:
                insert_columns.append(full_name_column)
                insert_values.append(full_name or username)
                insert_placeholders.append("%s")

            if role_column:
                insert_columns.append(role_column)
                insert_values.append("cashier")
                insert_placeholders.append("%s")

            query = f"INSERT INTO tbl_users ({', '.join(['`' + c + '`' for c in insert_columns])}) VALUES ({', '.join(insert_placeholders)})"

            # Save the new account into tbl_users
            cursor.execute(query, tuple(insert_values))
            connection.commit()

            # Auto-login after registration
            # Get the inserted user
            cursor.execute(f"SELECT * FROM tbl_users WHERE `{username_column}` = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            connection.close()
            if user:
                session["user_id"] = user.get(find_column(columns, ["user_id", "userid", "id"]) or "user_id")
                session["username"] = username
                session["full_name"] = user.get(full_name_column) or full_name or username
                session["role"] = user.get(role_column) or "cashier"
            else:
                session["user_id"] = username
                session["username"] = username
                session["full_name"] = full_name or username
                session["role"] = "cashier"
            return redirect(url_for("dashboard"))
        except Exception as e:
            cursor.close()
            connection.close()
            flash("Failed to create account.", "error")
            return render_template("register.html")

    return render_template("register.html")
@app.route("/", methods=["GET", "POST"])
def login():
    """Display the login page and process login."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Supports input name="username" or name="email".
        login_value = (
            request.form.get("username")
            or request.form.get("email")
            or request.form.get("login")
            or ""
        ).strip()

        password = request.form.get("password", "")

        if not login_value or not password:
            flash("Please enter your username/email and password.", "error")
            return render_template("login.html")

        user, error_message = find_user(login_value, password)

        if user:
            # Save the most useful fields that exist in the table.
            columns = get_table_columns("tbl_users")

            user_id_column = find_column(
                columns,
                ["user_id", "userid", "id"]
            )

            username_column = find_column(
                columns,
                ["username", "user_name", "email", "email_address"]
            )

            full_name_column = find_column(
                columns,
                ["full_name", "fullname", "name", "user_name"]
            )

            role_column = find_column(
                columns,
                ["role", "user_role", "type"]
            )

            session["user_id"] = (
                user.get(user_id_column)
                if user_id_column
                else login_value
            )

            session["username"] = (
                user.get(username_column)
                if username_column
                else login_value
            )

            session["full_name"] = (
                user.get(full_name_column)
                if full_name_column
                else login_value
            )

            session["role"] = (
                user.get(role_column)
                if role_column
                else "User"
            )

            return redirect(url_for("dashboard"))

        flash(error_message or "Login failed.", "error")

    return render_template("login.html")


# ------------------------------------------------------------
# DASHBOARD
# ------------------------------------------------------------
# Helper function to get row counts for any table
def get_table_count(table_name):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return count

# Helper function to get recent rows and column names for any table
def get_table_rows(table_name, limit=5):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name} ORDER BY 1 DESC LIMIT %s", (limit,))
    rows = cursor.fetchall()
    columns = [column[0] for column in cursor.description] if cursor.description else []
    cursor.close()
    conn.close()
    return rows, columns


@app.route("/dashboard")
def dashboard():
    """Display the laundry management dashboard."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Counts are based directly on the existing database tables.
    stats = {
        "customers": get_table_count("tbl_customers"),
        "orders": get_table_count("tbl_orders"),
        "inventory": get_table_count("tbl_inventory"),
        "payments": get_table_count("tbl_payments"),
    }

    # Recent orders (with customer name).
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT o.order_id, o.status, o.total_amount, o.order_date,
               COALESCE(c.customer_name, 'Unknown') AS customer_name
        FROM tbl_orders o
        LEFT JOIN tbl_customers c ON o.customer_id = c.customer_id
        ORDER BY o.order_id DESC
        LIMIT 5
        """
    )
    recent_orders = cursor.fetchall()

    # Order status counts for dashboard
    cursor.execute(
        """
        SELECT status, COUNT(*) as count
        FROM tbl_orders
        GROUP BY status
        """
    )
    status_rows = cursor.fetchall()
    status_counts = {
        "Pending": 0,
        "In Process": 0,
        "Ready": 0,
        "Claimed": 0,
        "Cancelled": 0
    }
    for row in status_rows:
        status_name = row.get("status") or ""
        if status_name == "Ready":
            status_counts["Claimed"] = (status_counts.get("Claimed") or 0) + (row.get("count") or 0)
        elif status_name in status_counts:
            status_counts[status_name] = row.get("count") or 0
        else:
            status_counts[status_name] = row.get("count") or 0

    total_orders_count = get_table_count("tbl_orders")
    cursor.close()
    connection.close()

    # Recent customers.
    recent_customers, customer_columns = get_table_rows(
        "tbl_customers",
        5
    )

    # Build a unified recent-activity feed from real data.
    activities = []
    for order in recent_orders:
        status = order.get("status", "")
        icon = "fa-check"
        color = "green"
        if status == "Pending":
            icon = "fa-clock"
            color = "orange"
        elif status == "In Process":
            icon = "fa-spinner"
            color = "blue"
        elif status == "Ready":
            icon = "fa-box"
            color = "blue"
        elif status == "Claimed":
            icon = "fa-check"
            color = "green"
        when = order.get("order_date")
        time_text = when.strftime("%b %d, %Y") if when else ""
        activities.append({
            "color": color,
            "icon": icon,
            "text": "Order #%s %s" % (order.get("order_id"), status),
            "time": time_text,
            "sort": when,
        })

    for customer in recent_customers:
        when = customer.get("created_at") if isinstance(customer, dict) else None
        # recent_customers come from get_table_rows (tuple-ish dict via cursor)
        if not isinstance(customer, dict):
            customer = dict(zip(customer_columns, customer)) if False else customer
        name = customer.get("customer_name") if isinstance(customer, dict) else None
        if name is None and isinstance(customer, (tuple, list)):
            # map by columns
            idx = customer_columns.index("customer_name") if "customer_name" in customer_columns else None
            name = customer[idx] if idx is not None else "Customer"
            created = customer[customer_columns.index("created_at")] if "created_at" in customer_columns else None
            when = created
        activities.append({
            "color": "purple",
            "icon": "fa-user",
            "text": "New customer %s added" % (name or "Customer"),
            "time": (when.strftime("%b %d, %Y") if hasattr(when, "strftime") else (str(when) if when else "")),
            "sort": when,
        })

    activities.sort(key=lambda a: (a["sort"] is not None, a["sort"]), reverse=True)
    activities = activities[:4]

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_orders=recent_orders,
        recent_customers=recent_customers,
        customer_columns=customer_columns,
        activities=activities,
        username=session.get("username", ""),
        full_name=session.get("full_name", ""),
        role=session.get("role", "User"),
        status_counts=status_counts,
        total_orders_count=total_orders_count
    )

# ------------------------------------------------------------
# CUSTOMERS
# ------------------------------------------------------------
@app.route("/customers", methods=["GET", "POST"])
def customers():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if connection is None:
        return "Could not connect to the database.", 500

    cursor = connection.cursor(dictionary=True)

    if request.method == "POST":
        customer_name = request.form.get("customer_name", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()

        if customer_name:
            cursor.execute(
                """
                INSERT INTO tbl_customers
                (customer_name, phone, address)
                VALUES (%s, %s, %s)
                """,
                (customer_name, phone, address)
            )
            connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("customers"))

    cursor.execute(
        """
        SELECT customer_id, customer_name, phone, address, created_at
        FROM tbl_customers
        ORDER BY customer_id DESC
        """
    )

    rows = cursor.fetchall()

    new_this_month = 0
    with_phone = 0
    with_address = 0

    for row in rows:
        created_at = row.get("created_at")

        if created_at and created_at.year == datetime.now().year \
                and created_at.month == datetime.now().month:
            new_this_month += 1

        if row.get("phone"):
            with_phone += 1

        if row.get("address"):
            with_address += 1

    cursor.close()
    connection.close()

    return render_template(
        "customer.html",
        rows=rows,
        total_customers=len(rows),
        new_this_month=new_this_month,
        with_phone=with_phone,
        with_address=with_address,
        full_name=session.get("full_name", "User"),
        role=session.get("role", "User")
    )


# ------------------------------------------------------------
# ORDERS
# ------------------------------------------------------------
@app.route("/orders", methods=["GET", "POST"])
def orders():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if connection is None:
        return "Could not connect to the database.", 500

    cursor = connection.cursor(dictionary=True)

    action = request.form.get("action")

    # MARK ORDER AS PAID
    if request.method == "POST" and action == "mark_paid":
        order_id = request.form.get("order_id")
        if order_id:
            # Get order total
            cursor.execute(
                "SELECT total_amount FROM tbl_orders WHERE order_id = %s",
                (order_id,)
            )
            order = cursor.fetchone()
            if order:
                total_amount = order.get("total_amount") or 0
                # Add payment record for full amount
                cursor.execute(
                    """
                    INSERT INTO tbl_payments
                    (order_id, amount_paid, payment_method, payment_date, received_by)
                    VALUES (%s, %s, %s, NOW(), %s)
                    """,
                    (order_id, total_amount, "Cash", session.get("user_id"))
                )
                # Update order payment status
                cursor.execute(
                    """
                    UPDATE tbl_orders
                    SET payment_status = 'Paid'
                    WHERE order_id = %s
                    """,
                    (order_id,)
                )
                connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for("orders"))

    # CREATE NEW ORDER
    if request.method == "POST":
        customer_id = request.form.get("customer_id")
        total_amount = request.form.get("total_amount")
        status = request.form.get("status") or "Pending"
        payment_method = request.form.get("payment_method") or "Cash"

        if customer_id and total_amount:
            cursor.execute(
                """
                INSERT INTO tbl_orders
                (customer_id, user_id, order_date, status, total_amount, payment_status, payment_method)
                VALUES (%s, %s, NOW(), %s, %s, 'Unpaid', %s)
                """,
                (customer_id, session.get("user_id"), status, total_amount, payment_method)
            )
            connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("orders"))

    # LIST ORDERS WITH CUSTOMER NAME
    cursor.execute(
        """
        SELECT
            o.order_id,
            o.customer_id,
            o.user_id,
            o.order_date,
            o.status,
            o.total_amount,
            o.payment_status,
            c.customer_name
        FROM tbl_orders o
        LEFT JOIN tbl_customers c
            ON o.customer_id = c.customer_id
        ORDER BY o.order_id DESC
        """
    )

    rows = cursor.fetchall()

    # Customers for the new order dropdown
    cursor.execute(
        """
        SELECT customer_id, customer_name
        FROM tbl_customers
        ORDER BY customer_name ASC
        """
    )

    customers = cursor.fetchall()

    cursor.close()
    connection.close()

    total_orders = len(rows)

    pending_count = 0
    in_process_count = 0
    ready_count = 0
    claimed_count = 0

    for row in rows:
        status = row.get("status")

        if status == "Pending":
            pending_count += 1
        elif status == "In Process":
            in_process_count += 1
        elif status == "Ready":
            ready_count += 1
        elif status == "Claimed":
            claimed_count += 1

    return render_template(
        "order.html",
        rows=rows,
        customers=customers,
        total_orders=total_orders,
        pending_count=pending_count,
        in_process_count=in_process_count,
        ready_count=ready_count,
        claimed_count=claimed_count
    )






# ------------------------------------------------------------
# INVENTORY
# ------------------------------------------------------------
@app.route("/inventory", methods=["GET", "POST"])
def inventory():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if connection is None:
        return "Could not connect to the database.", 500

    cursor = connection.cursor(dictionary=True)

    action = request.form.get("action")

    # ADJUST STOCK
    if request.method == "POST" and action == "adjust":
        item_id = request.form.get("item_id")
        stock_quantity = request.form.get("stock_quantity")
        reorder_level = request.form.get("reorder_level")

        if item_id and stock_quantity and reorder_level:
            cursor.execute(
                """
                UPDATE tbl_inventory
                SET stock_quantity = %s,
                    reorder_level = %s
                WHERE item_id = %s
                """,
                (stock_quantity, reorder_level, item_id)
            )
            connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("inventory"))

    # CREATE ITEM
    if request.method == "POST":
        item_name = request.form.get("item_name", "").strip()
        category = request.form.get("category", "").strip()
        unit = request.form.get("unit", "").strip()
        stock_quantity = request.form.get("stock_quantity")
        reorder_level = request.form.get("reorder_level")

        if item_name and stock_quantity and reorder_level:
            cursor.execute(
                """
                INSERT INTO tbl_inventory
                (item_name, category, unit, stock_quantity, reorder_level)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (item_name, category, unit, stock_quantity, reorder_level)
            )
            connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("inventory"))

    # LIST INVENTORY
    cursor.execute(
        """
        SELECT
            item_id,
            item_name,
            category,
            unit,
            stock_quantity,
            reorder_level,
            created_at
        FROM tbl_inventory
        ORDER BY item_id DESC
        """
    )

    rows = cursor.fetchall()

    cursor.close()
    connection.close()

    total_items = len(rows)
    total_units = 0
    low_stock_count = 0
    out_of_stock_count = 0

    for row in rows:
        quantity = int(row.get("stock_quantity") or 0)
        reorder = int(row.get("reorder_level") or 0)

        total_units += quantity

        if quantity <= 0:
            row["stock_state"] = "out-of-stock"
            row["stock_label"] = "Out of Stock"
            row["stock_percent"] = 0
            out_of_stock_count += 1

        elif quantity <= reorder:
            row["stock_state"] = "low-stock"
            row["stock_label"] = "Low Stock"
            row["stock_percent"] = min(int(quantity / reorder * 100), 100) if reorder else 0
            low_stock_count += 1

        else:
            row["stock_state"] = "in-stock"
            row["stock_label"] = "In Stock"
            # Full bar at 2x the reorder level.
            row["stock_percent"] = min(int(quantity / (reorder * 2) * 100), 100) if reorder else 100

    return render_template(
        "inventory.html",
        rows=rows,
        total_items=total_items,
        total_units=total_units,
        low_stock_count=low_stock_count,
        out_of_stock_count=out_of_stock_count
    )


# ------------------------------------------------------------
# PAYMENTS
# ------------------------------------------------------------
METHOD_META = {
    "Cash": ("cash", "fa-money-bill-wave"),
    "GCash": ("gcash", "fa-mobile-screen"),
    "Card": ("card", "fa-credit-card"),
}


def get_order_balances(cursor):
    """Return per-order paid totals and balances for every order."""
    cursor.execute(
        """
        SELECT
            o.order_id,
            o.customer_id,
            o.total_amount,
            o.status,
            c.customer_name,
            COALESCE(SUM(p.amount_paid), 0) AS total_paid
        FROM tbl_orders o
        LEFT JOIN tbl_customers c
            ON o.customer_id = c.customer_id
        LEFT JOIN tbl_payments p
            ON o.order_id = p.order_id
        GROUP BY
            o.order_id,
            o.customer_id,
            o.total_amount,
            o.status,
            c.customer_name
        ORDER BY o.order_id DESC
        """
    )

    balances = {}

    for row in cursor.fetchall():
        total_amount = float(row.get("total_amount") or 0)
        total_paid = float(row.get("total_paid") or 0)

        row["balance"] = round(total_amount - total_paid, 2)
        balances[row["order_id"]] = row

    return balances


@app.route("/payments", methods=["GET", "POST"])
def payments():
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    if connection is None:
        return "Could not connect to the database.", 500

    cursor = connection.cursor(dictionary=True)

    # RECORD PAYMENT
    if request.method == "POST":
        order_id = request.form.get("order_id")
        amount_paid = request.form.get("amount_paid")
        payment_method = request.form.get("payment_method")

        allowed_methods = ["Cash", "GCash", "Card"]

        if order_id and amount_paid and payment_method in allowed_methods:
            cursor.execute(
                """
                INSERT INTO tbl_payments
                (order_id, amount_paid, payment_method, payment_date, received_by)
                VALUES (%s, %s, %s, NOW(), %s)
                """,
                (order_id, amount_paid, payment_method, session.get("user_id"))
            )

            # Settle the order once the balance reaches zero.
            cursor.execute(
                """
                SELECT
                    o.total_amount,
                    COALESCE(SUM(p.amount_paid), 0) AS total_paid
                FROM tbl_orders o
                LEFT JOIN tbl_payments p
                    ON o.order_id = p.order_id
                WHERE o.order_id = %s
                GROUP BY o.order_id, o.total_amount
                """,
                (order_id,)
            )

            settlement = cursor.fetchone()

            if settlement:
                total_amount = float(settlement["total_amount"] or 0)
                total_paid = float(settlement["total_paid"] or 0)

                payment_status = "Paid" if total_paid >= total_amount else "Unpaid"

                cursor.execute(
                    """
                    UPDATE tbl_orders
                    SET payment_status = %s
                    WHERE order_id = %s
                    """,
                    (payment_status, order_id)
                )

            connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("payments"))

    # LIST PAYMENTS
    balances = get_order_balances(cursor)

    cursor.execute(
        """
        SELECT
            p.payment_id,
            p.order_id,
            p.amount_paid,
            p.payment_method,
            p.payment_date,
            p.received_by,
            u.full_name AS received_by_name,
            c.customer_name
        FROM tbl_payments p
        LEFT JOIN tbl_orders o
            ON p.order_id = o.order_id
        LEFT JOIN tbl_customers c
            ON o.customer_id = c.customer_id
        LEFT JOIN tbl_users u
            ON p.received_by = u.user_id
        ORDER BY p.payment_id DESC
        """
    )

    rows = cursor.fetchall()

    cursor.close()
    connection.close()

    total_payments = len(rows)
    total_collected = 0.0
    this_month_total = 0.0

    now = datetime.now()

    for row in rows:
        amount = float(row.get("amount_paid") or 0)
        total_collected += amount

        paid_at = row.get("payment_date")

        if paid_at and paid_at.year == now.year and paid_at.month == now.month:
            this_month_total += amount

        method_key, method_icon = METHOD_META.get(
            row.get("payment_method"),
            ("card", "fa-credit-card")
        )

        row["method_key"] = method_key
        row["method_icon"] = method_icon

        # Settlement is derived from the order balance, not a stored column.
        order = balances.get(row["order_id"])

        if order and order["balance"] <= 0:
            row["settlement_key"] = "paid"
            row["settlement_label"] = "Paid"
        elif order and order["balance"] > 0:
            row["settlement_key"] = "partial"
            row["settlement_label"] = "Partial"
        else:
            row["settlement_key"] = "unpaid"
            row["settlement_label"] = "Unpaid"

    average_payment = total_collected / total_payments if total_payments else 0.0

    unpaid_orders = [
        order for order in balances.values() if order["balance"] > 0
    ]

    return render_template(
        "payment.html",
        rows=rows,
        total_payments=total_payments,
        total_collected=total_collected,
        this_month_total=this_month_total,
        average_payment=average_payment,
        unpaid_orders=unpaid_orders
    )


# ------------------------------------------------------------
# USERS
# ------------------------------------------------------------
@app.route("/users")
def users():
    if "user_id" not in session:
        return redirect(url_for("login"))

    rows, columns = get_table_rows("tbl_users")

    return render_template(
        "users.html",
        rows=rows,
        columns=columns
    )


# ------------------------------------------------------------
# REPORTS
# ------------------------------------------------------------
@app.route("/reports")
def reports():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("reports.html")


# ------------------------------------------------------------
# LOGOUT
# ------------------------------------------------------------
@app.route("/logout")
def logout():
    """Clear the current user's session."""
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------
# ERROR HANDLERS
# ------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(error):
    return """
    <h1>404 - Page Not Found</h1>
    <p>The page you requested does not exist.</p>
    <p><a href="/">Return to Login</a></p>
    """, 404


# ------------------------------------------------------------
# START FLASK
# ------------------------------------------------------------
if __name__ == "__main__":
    # Open browser automatically
    threading.Timer(1.2, open_browser).start()
    print("=" * 60)
    print("LAUNDRY MANAGEMENT SYSTEM")
    print("=" * 60)
    print("Database: laundry_management")
    print("Server: http://127.0.0.1:5000")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )