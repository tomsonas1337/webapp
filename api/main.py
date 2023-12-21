from flask import Flask, jsonify, request
import mysql.connector
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import timedelta
import bcrypt
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
# Configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'test'
}

def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn
def get_user_id(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Prepare and execute the SQL query to get the UserID
        query = "SELECT UserID FROM Users WHERE Username = %s"
        cursor.execute(query, (username,))
        user_record = cursor.fetchone()

        # Check if a record was found
        if user_record:
            return user_record['UserID']
        else:
            return None

    except mysql.connector.Error as err:
        print("Error occurred:", err)
        return None

    finally:
        cursor.close()
        conn.close()
def check_user_role(required_roles):
    current_user_identity = get_jwt_identity()
    current_username = current_user_identity['username']  # Extract username from JWT identity

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT Role FROM Users WHERE Username = %s", (current_username,))
        user_record = cursor.fetchone()
        if user_record and user_record['Role'] in required_roles:
            return True
        return False

    finally:
        cursor.close()
        conn.close()


def query_database_for_user(username, password):
    # Database configuration
    db_config = {
        'host': 'localhost',
        'user': 'root',  # Replace with your database username
        'password': '',  # Replace with your database password
        'database': 'test'  # Replace with your database name
    }

    # Create a new database connection
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    try:
        # Prepare and execute the SQL query
        query = "SELECT * FROM Users WHERE Username = %s"
        cursor.execute(query, (username,))

        # Fetch one record
        user = cursor.fetchone()

        # Verify password (if user exists and password is provided)
        if user and password:
            stored_password = user['Password']  # Assuming the password field is named 'Password'
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                return user
            else:
                return None
        else:
            return None

    except mysql.connector.Error as err:
        print("Error occurred:", err)
        return None

    finally:
        cursor.close()
        conn.close()
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # Authenticate user here
    user = valid_user(username, password)
    if user:
        # Create a token with both the username and the UserID
        user_identity = {'username': username, 'user_id': user['UserID']}
        access_token = create_access_token(identity=user_identity, expires_delta=timedelta(days=1))
        response = jsonify(access_token=access_token, user_id=user['UserID'])
        print(response.get_data(as_text=True))  # Print the response for debugging
        return response

    return jsonify({"msg": "Bad username or password"}), 401
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
def valid_user(username, password):
    # Query the database for the user
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Prepare and execute the SQL query
        query = "SELECT * FROM Users WHERE Username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        # Verify password (if user exists and password is provided)
        if user:
            stored_password = user['Password']  # Assuming the password field is named 'Password'
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                return user  # Return the user object
        return None

    except mysql.connector.Error as err:
        print("Error occurred:", err)
        return None

    finally:
        cursor.close()
        conn.close()

@app.route('/api/users', methods=['GET', 'POST'])
@jwt_required()
def users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'GET':
        if not check_user_role(['admin']):
            return jsonify({"msg": "Access denied"}), 403
        cursor.execute("SELECT * FROM Users")
        users = cursor.fetchall()
        return jsonify(users)
    
    elif request.method == 'POST':
        if not check_user_role(['admin']):
            return jsonify({"msg": "Access denied"}), 403
        # Extract user details from request
        username = request.json['Username']
        email = request.json['Email']
        phone = request.json.get('Phone', None)
        password = request.json['Password']
        role = request.json.get('Role', 'user')  # Default role is 'user' if not specified

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert new user into the database
        query = "INSERT INTO Users (Username, Email, Phone, Password, Role) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (username, email, phone, hashed_password, role))
        conn.commit()
        return jsonify({"message": "User added successfully!"}), 201
    
@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def user_details(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity['user_id']
    if request.method == 'GET':
        if not (current_user_id == user_id or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403
        cursor.execute("SELECT * FROM Users WHERE UserID = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify(user)

    elif request.method == 'PUT':
        if not (current_user_id == user_id or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403
        username = request.json['Username']
        email = request.json['Email']
        phone = request.json.get('Phone', None)

        query = ("UPDATE Users SET Username=%s, Email=%s, Phone=%s WHERE UserID = %s")
        cursor.execute(query, (username, email, phone, user_id))
        conn.commit()
        return jsonify({"message": "User updated successfully!"})

    elif request.method == 'DELETE':
        if not check_user_role(['admin']):
            return jsonify({"msg": "Access denied"}), 403
        cursor.execute("DELETE FROM Users WHERE UserID = %s", (user_id,))
        conn.commit()
        return jsonify({"message": "User deleted successfully!"})

@app.route('/api/users/<int:user_id>/items', methods=['GET', 'POST'])
@jwt_required()
def user_items(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    current_user_identity = get_jwt_identity()
    if request.method == 'GET':
        if not (check_user_role(['user']) or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403
        query = ("SELECT Items.* FROM Items WHERE OwnerID = %s")
        cursor.execute(query, (user_id,))
        items = cursor.fetchall()
        return jsonify(items)

    elif request.method == 'POST':
        if not (check_user_role(['user']) or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403
        name = request.json['Name']
        description = request.json.get('Description', None)
        found_date = request.json['FoundDate']

        query = "INSERT INTO Items (Name, Description, OwnerID, FoundDate) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (name, description, user_id, found_date))
        conn.commit()
        return jsonify({"message": "Item added successfully!"}), 201
@app.route('/api/items', methods=['GET'])
@jwt_required()  # This will require a valid JWT in the request headers
def all_items():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM Items")
        items = cursor.fetchall()
        return jsonify(items)
    except mysql.connector.Error as err:
        print("Database error occurred:", err)
        return jsonify({"msg": "Internal server error"}), 500
    finally:
        cursor.close()
        conn.close()
@app.route('/api/items/<int:item_id>/comments', methods=['GET'])
@jwt_required()
def get_item_comments(item_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch item's name
        cursor.execute("SELECT Name FROM Items WHERE ItemID = %s", (item_id,))
        item = cursor.fetchone()
        item_name = item['Name'] if item else 'Unknown Item'

        # Fetch comments
        cursor.execute("""
            SELECT Comments.CommentText, Users.Username 
            FROM Comments 
            JOIN Users ON Comments.UserID = Users.UserID 
            WHERE Comments.ItemID = %s
        """, (item_id,))
        comments = cursor.fetchall()

        return jsonify({'itemName': item_name, 'comments': comments})
    except mysql.connector.Error as err:
        print("Database error occurred:", err)
        return jsonify({"msg": "Internal server error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/users/<int:user_id>/items/<int:item_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def user_item_details(user_id, item_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity['user_id']
    if request.method == 'GET':
        if not (check_user_role(['user']) or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403
        query = ("SELECT Items.* FROM Items WHERE OwnerID = %s AND ItemID = %s")
        cursor.execute(query, (user_id, item_id))
        item = cursor.fetchone()
        if not item:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(item)

    elif request.method == 'PUT':
        if not (check_user_role(['user']) or check_user_role(['admin'] or user_id == current_user_id)):
            return jsonify({"msg": "Access denied"}), 403
        name = request.json['Name']
        description = request.json.get('Description', None)
        found_date = request.json['FoundDate']

        query = ("UPDATE Items SET Name=%s, Description=%s, FoundDate=%s WHERE OwnerID = %s AND ItemID = %s")
        cursor.execute(query, (name, description, found_date, user_id, item_id))
        conn.commit()
        return jsonify({"message": "Item updated successfully!"})

    try:
        # First, delete comments associated with the item
        cursor.execute("DELETE FROM Comments WHERE ItemID = %s", (item_id,))
        conn.commit()

        # Then, delete the item itself
        cursor.execute("DELETE FROM Items WHERE OwnerID = %s AND ItemID = %s", (user_id, item_id))
        conn.commit()
        
        return jsonify({"message": "Item and associated comments deleted successfully!"})
    except mysql.connector.Error as err:
        conn.rollback()
        print("Error occurred:", err)
        return jsonify({"msg": "Failed to delete item and associated comments"}), 500

@app.route('/api/users/<int:user_id>/items/<int:item_id>/comments', methods=['GET', 'POST'])    
@jwt_required()
def item_comments(user_id, item_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity['user_id']
    
    if request.method == 'GET':
        if not (check_user_role(['user']) or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403
        query = """
        SELECT Comments.* FROM Comments
        JOIN Items ON Comments.ItemID = Items.ItemID
        JOIN Users ON Items.OwnerID = Users.UserID
        WHERE Comments.ItemID = %s AND Users.UserID = %s
        """
        cursor.execute(query, (item_id, user_id))  # Pass both item_id and user_id
        comments = cursor.fetchall()
        return jsonify(comments)

    elif request.method == 'POST':
        if not (current_user_id == user_id or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403
        comment_text = request.json['CommentText']

        query = """
        INSERT INTO Comments (ItemID, CommentText)
        SELECT %s, %s FROM Items
        WHERE Items.ItemID = %s AND Items.OwnerID = %s
        """
        cursor.execute(query, (item_id, comment_text))
        conn.commit()
        return jsonify({"message": "Comment added successfully!"}), 201

@app.route('/api/users/<int:user_id>/items/<int:item_id>/comments/<int:comment_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def comment_details(user_id, item_id, comment_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity['user_id']

    if request.method == 'GET':
        # Check for appropriate permissions
        if not (current_user_id == user_id or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403

        # Query to select a specific comment of a specific item from a specific user
        query = """
        SELECT Comments.* FROM Comments
        JOIN Items ON Comments.ItemID = Items.ItemID
        WHERE Comments.ItemID = %s AND Comments.CommentID = %s AND Items.OwnerID = %s
        """
        cursor.execute(query, (item_id, comment_id, user_id))
        comment = cursor.fetchone()
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404
        return jsonify(comment)

    elif request.method == 'PUT':
        # Check if the user is authorized to update the comment
        if not (current_user_id == user_id or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403

        comment_text = request.json['CommentText']
        # Update a specific comment of a specific item belonging to a specific user
        query = """
            UPDATE Comments SET CommentText = %s
            WHERE CommentID = %s AND ItemID = %s AND EXISTS (
                SELECT 1 FROM Items WHERE ItemID = %s AND OwnerID = %s
            )
            """
        cursor.execute(query, (comment_text, comment_id, item_id, item_id, user_id))
        conn.commit()
        return jsonify({"message": "Comment updated successfully!"})

    elif request.method == 'DELETE':
        # Check if the user is authorized to delete the comment
        if not (current_user_id == user_id or check_user_role(['admin'])):
            return jsonify({"msg": "Access denied"}), 403

        # Delete a specific comment of a specific item belonging to a specific user
        query = """
            DELETE FROM Comments
            WHERE CommentID = %s AND ItemID = %s AND EXISTS (
                SELECT 1 FROM Items WHERE ItemID = %s AND OwnerID = %s
            )
            """
        cursor.execute(query, (comment_id, item_id, item_id, user_id))
        conn.commit()
        return jsonify({"message": "Comment deleted successfully!"})
@app.route('/api/messages', methods=['POST'])
@jwt_required()
def send_message():
    current_user_id = get_jwt_identity()['user_id']
    receiver_id = request.json.get('receiver_id')
    message_text = request.json.get('message_text')

    if not message_text:
        return jsonify({"msg": "Message text is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        query = "INSERT INTO Messages (SenderID, ReceiverID, MessageText) VALUES (%s, %s, %s)"
        cursor.execute(query, (current_user_id, receiver_id, message_text))
        conn.commit()
        return jsonify({"message": "Message sent successfully"}), 201

    except mysql.connector.Error as err:
        print("Error occurred:", err)
        return jsonify({"msg": "Failed to send message"}), 500

    finally:
        cursor.close()
        conn.close()
@app.route('/api/messages', methods=['GET'])
@jwt_required()
def get_messages():
    current_user_id = get_jwt_identity()['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        query = "SELECT * FROM Messages WHERE ReceiverID = %s OR SenderID = %s"
        cursor.execute(query, (current_user_id, current_user_id))
        messages = cursor.fetchall()
        return jsonify(messages)

    except mysql.connector.Error as err:
        print("Error occurred:", err)
        return jsonify({"msg": "Failed to retrieve messages"}), 500

    finally:
        cursor.close()
        conn.close()
@app.route('/api/messages/<int:message_id>', methods=['PUT'])
@jwt_required()
def update_message(message_id):
    current_user_id = get_jwt_identity()['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        query = "UPDATE Messages SET IsRead = TRUE WHERE MessageID = %s AND ReceiverID = %s"
        cursor.execute(query, (message_id, current_user_id))
        conn.commit()
        return jsonify({"message": "Message updated successfully"})

    except mysql.connector.Error as err:
        print("Error occurred:", err)
        return jsonify({"msg": "Failed to update message"}), 500

    finally:
        cursor.close()
        conn.close()

app.config['JWT_SECRET_KEY'] = 'hsg;lkysdfg86123'  # Change this!
jwt = JWTManager(app)
if __name__ == '__main__':
    app.run(debug=True)
