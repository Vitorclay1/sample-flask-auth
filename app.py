from flask import Flask, request, jsonify
from database import db
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)

# Secret key for session management. Replace 'FIGSAJCFNlafsckrfbcbequwea' with your desired secret key.
app.config['SECRET_KEY'] = "FIGSAJCFNlafsckrfbcbequwea"

# SQLite database URI. Replace 'database.db' with your desired SQLite database name.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and user.password_hash == password:
            login_user(user)  # This will set the current user for the request context.
            print(current_user.is_authenticated)
            return jsonify({"message": "Logged in successfully"})
        
        return jsonify({"mesage": "Authenticated"})

    return jsonify({"message": "credentials invalid"}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    if current_user.is_authenticated:
        logout_user()
        print(current_user.is_authenticated)
        return jsonify({"message": "Logged out successfully"})

@app.route('/user', methods=['POST'])
@login_required
def create_user():
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    if username and password:
        if User.query.filter_by(username=username).first():
            return jsonify({"message": "Username already exists"}), 400
        
        user = User(username=username, password_hash=password)

        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    return jsonify({"message": "invalid data"}),401
    
@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def read_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"username": user.username})
    return jsonify({"message": "User not found"}), 404

@app.route('/user/<user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    password = data.get('password', '')

    if password:
        user = User.query.get(user_id)
        if user:
            user.password_hash = password
            db.session.commit()
            return jsonify({"message": "User updated successfully"}), 200
        return jsonify({"message": "User not found"}), 404
    return jsonify({"message": "invalid data"}), 400

@app.route('/user/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user_id != current_user.id:
        return jsonify({"message": "Unauthorized"}), 403
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    return jsonify({"message": "User not found"}), 404

@app.route('/', methods=['GET'])
def hello_world():
    return "hello world"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)