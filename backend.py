from flask import Flask, request, jsonify, send_file, url_for, render_template, redirect, flash, get_flashed_messages, Response
from flask_cors import CORS, cross_origin
from werkzeug.security import generate_password_hash, check_password_hash
import pymongo
from bson import ObjectId
from gridfs import GridFS
import re
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import jwt
import datetime
from urllib.parse import quote_plus

app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SECRET_KEY'] = 'KMJ123456789'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Gmail's SMTP port for TLS
app.config['MAIL_USE_TLS'] = True  # Use TLS encryption
app.config['MAIL_USERNAME'] = 'karenzijoslyn@gmail.com'
app.config['MAIL_PASSWORD'] = 'coup yusl ijqn bden'

mail = Mail(app)
SECRET_KEY = 'kmj12345'
s = URLSafeTimedSerializer('kmj12345')
username = 'jkarenzi'
password = '@Karenzijoslyn46'
encoded_username = quote_plus(username)
encoded_password = quote_plus(password)
url = f"mongodb+srv://{encoded_username}:{encoded_password}@knowledgebridge.q5ir04n.mongodb.net/?retryWrites=true&w=majority"

def highlight_search_keyword(text, keyword):
    # Use a simple HTML <mark> tag for highlighting
    if keyword:
        highlighted_text = text.replace(keyword, f'<mark>{keyword}</mark>')
        print(highlighted_text)
        print(type(text))
        return highlighted_text
    else:
        return text


def upload_picture(pic, username, email):
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_profile_pictures"]
    fs = GridFS(db)

    try:
        file_id = fs.put(pic, username=username, email=email)
        client.close()
        return {'file_id': str(file_id)}
    except Exception as e:
        print(e)
        return {'msg': 'unsuccessful'}

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def decode_token(auth_token):  
    try:  
        auth_token = auth_token.split(' ')
        token = auth_token[1]
    except:
        return {'message': 'Missing token', 'code':4}


    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
            print(user_id)
            return {'user_id': user_id, 'code':1}
        except jwt.ExpiredSignatureError:
            return {'message': 'Expired token', 'code':2}  # Token has expired
            
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token', 'code':3}  # Invalid token
    else:
        return {'message': 'Missing token', 'code':4} # missing token
    

@app.route('/login', methods=['POST'])
def get_login_data():
    try:
        form_data = request.get_json()
        username = form_data.get('username')
        password = form_data.get('password')

        client = pymongo.MongoClient(url)
        db = client["xtracker"]
        xtracker_users = db['xtracker_users']
        user_record = xtracker_users.find_one({'username':username})
        

        if user_record:
            stored_password = user_record['password']
            if check_password_hash(stored_password, password):
                user_id = str(user_record.get('_id'))
                print(user_id)
                token = generate_token(user_id)

                user_info = {
                    'user_id': user_id,
                    'username': user_record.get('username'),
                    'email': user_record.get('email'),
                    'confirmed': user_record.get('confirmed'),
                    'admin': user_record.get('admin'),
                    'profile_url': user_record.get('profile_url')
                }

                response = {'message':"Login successful", 'status':'ok', 'token': token, 'user_info': user_info}
                client.close()
                return jsonify(response)
            else:
                client.close()
                response = {'message':"Invalid password", 'status':'Not ok'}
                return jsonify(response)
        else:
            client.close()
            response = {'message':"Invalid credentials", 'status':'Not ok'}
            return jsonify(response)    
    except Exception as e:
        print(e)
        client.close()
        response = {'message':"Unsuccessful", 'status':'Not ok'}
        return jsonify(response)
    

@app.route('/signup', methods=['POST'])
def signup():
        try:
            form_data = request.get_json()
            username = form_data.get('username')
            password = form_data.get('password')
            email = form_data.get('email')
            role = form_data.get('role')

            client = pymongo.MongoClient(url)
            db = client["xtracker"]
            xtracker_users = db['xtracker_users']
            user_record = xtracker_users.find_one({'username': username})
            user_email = xtracker_users.find_one({'email': email})
            
            if user_email:
                client.close()
                response = {'message':"Email already in use", 'status':'not ok'}
                return jsonify(response)
            
            if not user_record:
                hashed_password = generate_password_hash(password)
                if role == 'admin':
                    data = {'username': username, 'password': hashed_password, 'email': email, 'confirmed': False, 'admin':True,'profile_url':'http://localhost:5000/user_profile/65391ee51bce770b901d1eb8'}
                    xtracker_users.insert_one(data)
                    
                else:
                    data = {'username': username, 'password': hashed_password, 'email': email, 'confirmed': False, 'admin':False,'profile_url':'http://localhost:5000/user_profile/65391ee51bce770b901d1eb8'}
                    xtracker_users.insert_one(data)
                    

                token = s.dumps(email)
                msg = Message('Confirm Email', sender='karenzijoslyn@gmail.com', recipients=[email])
                link = url_for('confirm_token', token=token, _external=True)
                msg.body = 'Your link is {}'.format(link)
                mail.send(msg)
            
                response = {'message':"Signup successful", 'status':'ok'}
                client.close()
                return jsonify(response)
            else:
                client.close()
                response = {'message':"Username already exists. Please choose a different one", 'status':'Not ok'}
                return jsonify(response)                  
        except Exception as e:
            print(e)
            client.close()
            response = {'message':"Unsuccessful", 'status':'Not ok'}
            return jsonify(response)
        
    
@app.route('/add_user', methods=['POST'])   
def add_user():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role')
        profile_picture = request.files.get('profile')
        

        client = pymongo.MongoClient(url)
        db = client["xtracker"]
        xtracker_users = db['xtracker_users']
        user_record = xtracker_users.find_one({'username': username})
        user_email = xtracker_users.find_one({'email': email})
        
        if user_email:
            client.close()
            response = {'message':"Email already in use", 'status':'not ok'}
            return jsonify(response)
        
        if not user_record:
            if not profile_picture:
                hashed_password = generate_password_hash(password)
                if role == 'admin':
                    data = {'username': username, 'password': hashed_password, 'email': email, 'confirmed': False, 'admin':True, 'profile_url':'http://localhost:5000/user_profile/65391ee51bce770b901d1eb8'}
                    xtracker_users.insert_one(data)
                    client.close()
                else:
                    data = {'username': username, 'password': hashed_password, 'email': email, 'confirmed': False, 'admin':False, 'profile_url':'http://localhost:5000/user_profile/65391ee51bce770b901d1eb8'}
                    xtracker_users.insert_one(data)
                    client.close()

                token = s.dumps(email)
                msg = Message('Confirm Email', sender='karenzijoslyn@gmail.com', recipients=[email])
                link = url_for('confirm_token', token=token, _external=True)
                msg.body = 'Your link is {}'.format(link)
                mail.send(msg)
            
                response = {'message':"Signup successful", 'status':'ok'}
                return jsonify(response)
            else:
                user_res = upload_picture(profile_picture, username, email)
                print(user_res)
                file_id = user_res.get('file_id', None)
                print(file_id)
                if not file_id:
                    return jsonify({'message':"Unsuccessful", 'status':'Not ok'})
                else:
                    hashed_password = generate_password_hash(password)
                    if role == 'admin':
                        data = {'username': username, 'password': hashed_password, 'email': email, 'confirmed': False, 'admin':True, 'profile_url': f'http://localhost:5000/user_profile/{file_id}'}
                        xtracker_users.insert_one(data)
                        client.close()
                    else:
                        data = {'username': username, 'password': hashed_password, 'email': email, 'confirmed': False, 'admin':False, 'profile_url': f'http://localhost:5000/user_profile/{file_id}'}
                        xtracker_users.insert_one(data)
                        client.close()

                    token = s.dumps(email)
                    msg = Message('Confirm Email', sender='karenzijoslyn@gmail.com', recipients=[email])
                    link = url_for('confirm_token', token=token, _external=True)
                    msg.body = 'Your link is {}'.format(link)
                    mail.send(msg)

                    response = {'message':"Signup successful", 'status':'ok'}
                    return jsonify(response)
        else:
            response = {'message':"Username already exists. Please choose a different one", 'status':'Not ok'}
            return jsonify(response)            
    except Exception as e:
        print(e)
        response = {'message':"Unsuccessful", 'status':'Not ok'}
        return jsonify(response)


@app.route('/user_profile/<string:id>')
def user_profile(id):
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_profile_pictures"]
    fs = GridFS(db)

    if id == '65391ee51bce770b901d1eb8':
        default_file = fs.get(ObjectId(id))
        response = Response(default_file.read(), content_type='image/png')
        client.close()
        return response
    
    file = fs.get(ObjectId(id))
    if file is None:
        default_file = fs.get(ObjectId('65391ee51bce770b901d1eb8'))
        response = Response(default_file.read(), content_type='image/png')
        client.close()
        return response
    
    response = Response(file.read(), content_type='image/jpeg')
    client.close()
    return response


@app.route('/confirm_email/<token>')
def confirm_token(token):
    try:
        email = s.loads(token, max_age=3600)
        client = pymongo.MongoClient(url)
        db = client["xtracker"]
        xtracker_users = db['xtracker_users']
        user_record = xtracker_users.find_one({'email': email})
        if user_record:
            query = {'email': email}
            update = {'$set': {'confirmed': True}}
            xtracker_users.update_one(query, update)
            the_msg = 'Email successfully verified'
            return render_template('verified.html', msg=the_msg, code=1)

    except SignatureExpired:
        the_msg = 'Link is expired'
        return render_template('verified.html', msg=the_msg, code=0)
    except BadSignature:
        the_msg = 'Invalid link'
        return render_template('verified.html', msg=the_msg, code=0)
    
    
@app.route('/reset_password/<token>')
def reset_password(token):
    print(token)
    try:
        email = s.loads(token, max_age=3600)
        return render_template('reset.html', token=token, email=email, code=1)
    except SignatureExpired:
        the_msg='This password reset link has expired.'
        return render_template('verified.html', msg=the_msg, code=0)
    except BadSignature:
        the_msg='Unauthorized access'
        return render_template('verified.html', msg=the_msg, code=0)


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
        form_data = request.get_json()
        email = form_data.get('email')
        client = pymongo.MongoClient(url)
        db = client["xtracker"]
        xtracker_users = db['xtracker_users']
        user_record = xtracker_users.find_one({'email': email})
        if not user_record:
            return jsonify({'message':'Account could not be found', 'status': 'not ok'})

        token = s.dumps(email)
        try:
            msg = Message('Reset Password', sender='karenzijoslyn@gmail.com', recipients=[email])
            link = f'http://localhost:5000/reset_password/{token}'
            msg.body = 'Your link to reset password is {}'.format(link)
            mail.send(msg)
            return jsonify({'message':'Password reset link sent successfully','status': 'ok'})
        except Exception as e:
            print(e)
            return jsonify({'message':'Could not send password reset link', 'status': 'not ok'})
        

@app.route('/password_reset', methods=['POST'])
def password_reset():
    token = request.form.get('token')
    password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')   

    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(f'/reset_password/{token}')
    
    try:
        client = pymongo.MongoClient(url)
        db = client["xtracker"]
        xtracker_users = db['xtracker_users']
        email = s.loads(token, max_age=3600)
        user_record = xtracker_users.find_one({'email': email})
        hashed_password = generate_password_hash(password)
            
        if user_record:
            query = {'email': email}
            update = {'$set': {'password': hashed_password}}
            
            xtracker_users.update_one(query, update)
            the_msg = 'Password has been successfully changed'
            client.close()
            return render_template('verified.html', msg=the_msg, code=1)
        
    except SignatureExpired:
        client.close()
        the_msg = 'The link has expired. Please try again'
        return render_template('verified.html', msg=the_msg, code=0)
    
    except BadSignature:
        client.close()
        the_msg = 'Invalid link'
        return render_template('verified.html', msg=the_msg, code=0)    


@app.route('/get_users')
def get_users():
    auth_token = request.headers.get('Authorization')
    auth_res = decode_token(auth_token)

    if auth_res['code'] != 1:
        return jsonify(auth_res)
    
    number_users = int(request.args.get('users'))
    query = request.args.get('query')
    roles = request.args.get('roles')
    status = request.args.get('status')

    client = pymongo.MongoClient(url)
    db = client["xtracker"]
    xtracker_users = db['xtracker_users']

    if not roles  and  not status:
        if query:
            regex_pattern = re.compile(query, re.IGNORECASE)
            users = xtracker_users.find({"$or": [{"username": {"$regex": regex_pattern}}, {"email": {"$regex": regex_pattern}}]}).skip(number_users).limit(10)
        else:
            users = xtracker_users.find({}).skip(number_users).limit(10)
    else:
        if query:
            regex_pattern = re.compile(query, re.IGNORECASE)
            if roles and status:
                roles = roles.split(',')
                for role in roles:
                    if role == 'admin':
                        roles[roles.index(role)] = True
                    else:
                        roles[roles.index(role)] = False

                status = status.split(',')
                for x_s in status:
                    if x_s == 'confirmed':
                        status[status.index(x_s)] = True
                    else:
                        status[status.index(x_s)] = False

                users = xtracker_users.find({'$and': [{"admin": {"$in": roles}}, {"confirmed": {"$in": status}}, {"$or": [{"username": {"$regex": regex_pattern}}, {"email": {"$regex": regex_pattern}}]}]}).skip(number_users).limit(10)
            elif roles and not status:
                roles = roles.split(',')
                for role in roles:
                    if role == 'admin':
                        roles[roles.index(role)] = True
                    else:
                        roles[roles.index(role)] = False
                
                users = xtracker_users.find({'$and': [{"admin": {"$in": roles}}, {"$or": [{"username": {"$regex": regex_pattern}}, {"email": {"$regex": regex_pattern}}]}]}).skip(number_users).limit(10)
            elif not roles and status:
                status = status.split(',')
                for x_s in status:
                    if x_s == 'confirmed':
                        status[status.index(x_s)] = True
                    else:
                        status[status.index(x_s)] = False

                users = xtracker_users.find({'$and': [{"confirmed": {"$in": status}}, {"$or": [{"username": {"$regex": regex_pattern}}, {"email": {"$regex": regex_pattern}}]}]}).skip(number_users).limit(10)
        else:
            if roles and status:
                roles = roles.split(',')
                for role in roles:
                    if role == 'admin':
                        roles[roles.index(role)] = True
                    else:
                        roles[roles.index(role)] = False

                status = status.split(',')
                for x_s in status:
                    if x_s == 'confirmed':
                        status[status.index(x_s)] = True
                    else:
                        status[status.index(x_s)] = False

                users = xtracker_users.find({'$and': [{"admin": {"$in": roles}}, {"confirmed": {"$in": status}}]}).skip(number_users).limit(10)
            elif roles and not status:
                roles = roles.split(',')
                for role in roles:
                    if role == 'admin':
                        roles[roles.index(role)] = True
                    else:
                        roles[roles.index(role)] = False

                users = xtracker_users.find({"admin": {"$in": roles}}).skip(number_users).limit(10)
            elif not roles and status:
                status = status.split(',')
                for x_s in status:
                    if x_s == 'confirmed':
                        status[status.index(x_s)] = True
                    else:
                        status[status.index(x_s)] = False

                users = xtracker_users.find({"confirmed": {"$in": status}}).skip(number_users).limit(10)

    users_list = [{
        'user_id': str(user.get('_id')),
        'username': user.get('username'),
        'password': user.get('password'),
        'email': user.get('email'),
        'confirmed': user.get('confirmed'),
        'admin': user.get('admin'),
        'profile_url': user.get('profile_url')
        } for user in users
    ]

    client.close()
    return jsonify({'users': users_list, 'code':0})


@app.route('/add_books', methods=['POST'])
def add_books():
    category = request.form.get('category')
    level = request.form.get('level')
    pdf_files = request.files.getlist('files')
    print(pdf_files)

    # Connect to MongoDB
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge"]
    fs = GridFS(db)
    
    try:
        # Save the PDF files to GridFS
        for pdf_file in pdf_files:
            file_id = fs.put(pdf_file, filename=pdf_file.filename, category=category, level=level)

        client.close()
        # Return a JSON response
        return jsonify({
            'status': 'success',
            'message': 'The PDF files have been uploaded successfully.'
        })
    except:
        client.close()
        return jsonify({
            'status': 'fail',
            'message': 'Could not upload pdf file!. Try again later'
        })
    

@app.route('/get_books')
def get_books():
    auth_token = request.headers.get('Authorization')
    auth_res = decode_token(auth_token)

    if auth_res['code'] != 1:
        return jsonify(auth_res)
    # Fetch all PDF files from GridFS
    number_books = int(request.args.get('books'))
    query = request.args.get('query')
    categories = request.args.get('categories')
    levels = request.args.get('levels')
    print(categories)
    print(levels)

    # Connect to MongoDB
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge"]
    fs = GridFS(db)

    if not categories  and  not levels:
        if query:
            regex_pattern = re.compile(query, re.IGNORECASE)
            pdf_files = fs.find({"$or": [{"filename": {"$regex": regex_pattern}}, {"category": {"$regex": regex_pattern}}]}).skip(number_books).limit(10)
        else:
            pdf_files = fs.find({}).skip(number_books).limit(10)
    else:
        if query:
            regex_pattern = re.compile(query, re.IGNORECASE)
            if categories and levels:
                categories = categories.split(',')
                levels = levels.split(',')
                pdf_files = fs.find({'$and': [{"category": {"$in": categories}}, {"level": {"$in": levels}}, {"$or": [{"filename": {"$regex": regex_pattern}}, {"category": {"$regex": regex_pattern}}]}]}).skip(number_books).limit(10)
            elif categories and not levels:
                categories = categories.split(',')
                print('yupeeeeeeeeeeeeeee')
                pdf_files = fs.find({'$and': [{"category": {"$in": categories}}, {"$or": [{"filename": {"$regex": regex_pattern}}, {"category": {"$regex": regex_pattern}}]}]}).skip(number_books).limit(10)
            elif not categories and levels:
                levels = levels.split(',')
                pdf_files = fs.find({'$and': [{"level": {"$in": levels}}, {"$or": [{"filename": {"$regex": regex_pattern}}, {"category": {"$regex": regex_pattern}}]}]}).skip(number_books).limit(10)
               
        else:
            if categories and levels:
                categories = categories.split(',')
                levels = levels.split(',')
                pdf_files = fs.find({'$and': [{"category": {"$in": categories}}, {"level": {"$in": levels}}]}).skip(number_books).limit(10)
            elif categories and not levels:
                categories = categories.split(',')
                print(categories)
                pdf_files = fs.find({"category": {"$in": categories}}).skip(number_books).limit(10)
            elif not categories and levels:
                levels = levels.split(',')
                pdf_files = fs.find({"level": {"$in": levels}}).skip(number_books).limit(10)

    

    # Create a list of dictionaries containing information about the PDF books
    books_data = [{'filename': file.filename, 'file_id': str(file._id), 'category': file.category, 'level': file.level} for file in pdf_files]
    print(books_data)
    client.close()

    # Return the list as JSON
    return jsonify({'pdf_books': books_data, 'code':0})    


@app.route('/download/<string:file_id>')
def download_file(file_id):
    # Connect to MongoDB
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge"]
    fs = GridFS(db)

    # Fetch the requested PDF file from GridFS
    file_id = ObjectId(file_id)
    file = fs.get(file_id)
    if file is None:
        client.close()
        return 'File not found', 404

    # Serve the PDF file for download
    response = send_file(
        file,
        as_attachment=True,
        download_name=file.filename,
        mimetype='application/pdf'
    )
    client.close()
    return response


@app.route('/get_pdf/<string:file_id>')
def get_pdf(file_id):
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge"]
    fs = GridFS(db)

    # Retrieve the PDF from GridFS by file_id
    try:
        pdf_file = fs.get(ObjectId(file_id))
    except:
        client.close()
        return jsonify({'msg': 'Invalid Objectid'}), 404

    # Check if the file exists
    if pdf_file is None:
        client.close()
        return "File not found", 404

    # Send the PDF as a response
    response = Response(pdf_file.read(), content_type='application/pdf')
    response.headers['Content-Disposition'] = f'inline; filename={pdf_file.filename}'
    client.close()
    return response


@app.route('/delete_user/<string:id>', methods=['DELETE'])
def delete_user(id):
    auth_token = request.headers.get('Authorization')
    auth_res = decode_token(auth_token)

    if auth_res['code'] != 1:
        return jsonify(auth_res)
    
    client = pymongo.MongoClient(url)
    db = client["xtracker"]
    xtracker_users = db['xtracker_users']
    result = xtracker_users.delete_one({'_id': ObjectId(id)})
    client.close()

    if result.deleted_count == 1:
       return jsonify({'msg': 'User deleted successfully','code':0})
        
    else:
        return jsonify({'msg': 'User not found','code':0})
    

@app.route('/delete_book/<string:id>', methods=['DELETE'])
def delete_book(id):
    auth_token = request.headers.get('Authorization')
    auth_res = decode_token(auth_token)

    if auth_res['code'] != 1:
        return jsonify(auth_res)
    
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge"]
    fs = GridFS(db)

    if fs.exists(ObjectId(id)):
        try:
            # Attempt to delete the file
            fs.delete(ObjectId(id))
            client.close()
            return jsonify({'msg': 'Book deleted successfully','code':0})
        except Exception as e:
            # Handle any exceptions that may occur during deletion
            print("Error deleting the file:", e)
            client.close()
            return jsonify({'msg': 'Error deleting book','code':0})
    else:
        client.close()
        return jsonify({'msg': 'Book not found', 'code':0})
    

@app.route('/add_question', methods=['POST'])
def add_question():
    id = request.form.get('id')
    question = request.form.get('question')
    timestamp = datetime.datetime.fromisoformat(request.form.get('timestamp'))


    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_community_questions"]
    questions = db['questions']

    data = {'user_id': id, 'question':question, 'created_at':timestamp}
    try:
        questions.insert_one(data)
        client.close()
        return jsonify({'message':'Successful', 'status': 'ok'})
    except Exception as e:
        client.close()
        return jsonify({'message':'Unsuccessful', 'status': 'not ok'})


@app.route('/get_questions')
def get_questions():
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_community_questions"]
    questions = db['questions']

    number_questions = int(request.args.get('questions'))
    query = request.args.get('query')

    if query:
        
        regex_pattern = re.compile(query, re.IGNORECASE) 
        results = questions.find({"question": {"$regex": regex_pattern}}).skip(number_questions).limit(3).sort("created_at", -1)
    else:
        results = questions.find().skip(number_questions).limit(3).sort("created_at", -1)

    
    db = client["xtracker"]
    xtracker_users = db['xtracker_users']

    list_results = []
    for result in results:
        user_record = xtracker_users.find_one(ObjectId(result.get('user_id')))
        datetime_object = datetime.datetime.strptime(str(result.get('created_at')), '%Y-%m-%d %H:%M:%S.%f')
        formatted_date = datetime_object.strftime('%b %d, %I:%M%p')
        object = {
            'question_id': str(result.get('_id')),
            'username': user_record.get('username'),
            'email': user_record.get('email'),
            'profile_url': user_record.get('profile_url'),
            'created_at': formatted_date,
            'question': highlight_search_keyword(result.get('question'),query),
        }
        list_results.append(object)

    client.close()
    return jsonify({'questions': list_results, 'status':'ok'})


@app.route('/add_post', methods=['POST'])
def add_post():
    id = request.form.get('id')
    user_post = request.form.get('user_post')
    timestamp = datetime.datetime.fromisoformat(request.form.get('timestamp'))

    if not id:
        return jsonify({'message':'User not found', 'status': 'not ok'})

    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_community_questions"]
    posts = db['posts']

    data = {
        'user_id': id,
        'user_post':user_post, 
        'created_at':timestamp,
        'likes': 0,
        'dislikes': 0,
        'comments':0
    }

    try:
        posts.insert_one(data)
        client.close()
        return jsonify({'message':'Successful', 'status': 'ok'})
    except Exception as e:
        client.close()
        return jsonify({'message':'Unsuccessful', 'status': 'not ok'})


@app.route('/get_posts')
def get_posts():
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_community_questions"]
    posts = db['posts']

    query = request.args.get('query')
    number_posts = int(request.args.get('posts'))

    if query:
        regex_pattern = re.compile(query, re.IGNORECASE) 
        results = posts.find({"user_post": {"$regex": regex_pattern}}).skip(number_posts).limit(1).sort("created_at", -1)
    else:
        results = posts.find().sort("created_at", -1).skip(number_posts).limit(1).sort("created_at", -1)


    db = client["xtracker"]
    xtracker_users = db['xtracker_users']

    list_results = []
    for result in results: 
        user_record = xtracker_users.find_one(ObjectId(result.get('user_id')))
        datetime_object = datetime.datetime.strptime(str(result.get('created_at')), '%Y-%m-%d %H:%M:%S.%f')
        formatted_date = datetime_object.strftime('%b %d, %I:%M%p')
        object = {
            'post_id': str(result.get('_id')),
            'username': user_record.get('username'),
            'email': user_record.get('email'),
            'profile_url': user_record.get('profile_url'),
            'created_at': formatted_date,
            'user_post': highlight_search_keyword(result.get('user_post'), query),
            'likes': result.get('likes'),
            'dislikes': result.get('dislikes'),
            'comments': result.get('comments')
        }
        list_results.append(object)

    client.close()
    return jsonify({'posts': list_results, 'status':'ok'})
    

@app.route('/remove_picture/<string:id>', methods=['DELETE'])    
def remove_picture(id):
    client = pymongo.MongoClient(url)
    db = client["xtracker"]
    xtracker_users = db['xtracker_users']

    user_record = xtracker_users.find_one({'_id':ObjectId(id)})

    if user_record:
        query = {'_id':ObjectId(id)}
        update = {'$set': {'profile_url': 'http://localhost:5000/user_profile/65391ee51bce770b901d1eb8'}}  
        xtracker_users.update_one(query, update)

        db = client["knowledgebridge_profile_pictures"]
        fs = GridFS(db)

        profile_record = fs.find_one({'username': user_record.get('username')})
        if profile_record:
            try:
                fs.delete(profile_record._id)
    
                db = client["xtracker"]
                xtracker_users = db['xtracker_users']
                userInfo = xtracker_users.find_one({'_id':ObjectId(id)})

                user_info = {
                    'user_id': str(userInfo.get('_id')),
                    'username': userInfo.get('username'),
                    'email': userInfo.get('email'),
                    'confirmed': userInfo.get('confirmed'),
                    'admin': userInfo.get('admin'),
                    'profile_url': userInfo.get('profile_url')
                }
                client.close()
                return jsonify({'message':'Profile picture successfully removed from database', 'status':'ok','user_info':user_info})
            except: 
                client.close()
                return jsonify({'message':'Unsuccessful', 'status': 'not ok'})
        else:
            client.close()
            return jsonify({'message':'No match found', 'status': 'not ok'})
    else:
        client.close()
        return jsonify({'message':'No match found', 'status': 'not ok'})
    

@app.route('/change_profile', methods=['POST'])
def change_profile():
    username= request.form.get('user') 
    profile_picture = request.files.get('profile_picture')
    email = request.form.get('email')

    print(username)
    print(profile_picture)
    print(email)

    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_profile_pictures"]
    fs = GridFS(db)

    profile_record = fs.find_one({'username': username})

    if profile_record:
        try:
            fs.delete(profile_record._id)
        except Exception as e:
            print(e)
            client.close()
            return jsonify({'message':"Unsuccessful", 'status':'Not ok'})
   
    try:
        user_res = upload_picture(profile_picture, username, email)
        print(user_res)
        file_id = user_res.get('file_id', None)
        print(file_id)
        if not file_id:
            client.close()
            return jsonify({'message':"Unsuccessful", 'status':'Not ok'})
        else:
            db = client["xtracker"]
            xtracker_users = db['xtracker_users']

            query = {'username':username}
            update = {'$set': {'profile_url': f'http://localhost:5000/user_profile/{file_id}'}}  
            xtracker_users.update_one(query, update)
            userInfo = xtracker_users.find_one({'username':username})

            user_info = {
                'user_id': str(userInfo.get('_id')),
                'username': userInfo.get('username'),
                'email': userInfo.get('email'),
                'confirmed': userInfo.get('confirmed'),
                'admin': userInfo.get('admin'),
                'profile_url': userInfo.get('profile_url')
            }
            print(user_info)

            client.close()
            return jsonify({'message':'Profile picture successfully changed!', 'status': 'ok', 'user_info':user_info})
    except Exception as e:
        print(e)
        client.close()
        return jsonify({'message':'Unable to change profile picture', 'status': 'not ok'})    
          

@app.route('/change_username', methods=['POST'])
def change_username():
    password = request.form.get('password')   
    old_username = request.form.get('old_username') 
    new_username = request.form.get('new_username')  

    client = pymongo.MongoClient(url)
    db = client["xtracker"]
    xtracker_users = db['xtracker_users']

    user_record = xtracker_users.find_one({'username': old_username})
    if user_record:
        stored_password = user_record['password']
        if check_password_hash(stored_password, password):
            try:
                query = {'username': old_username}
                update = {'$set': {'username': new_username}}  
                xtracker_users.update_one(query, update)
                new_user = xtracker_users.find_one({'username': new_username})
                user_info = {
                    'user_id': str(new_user.get('_id')),
                    'username': new_user.get('username'),
                    'email': new_user.get('email'),
                    'confirmed': new_user.get('confirmed'),
                    'admin': new_user.get('admin'),
                    'profile_url': new_user.get('profile_url')
                }

                client.close()
                return jsonify({'message': 'Username succesfully updated!', 'status':'ok','user_info':user_info})
            except Exception as e:
                print(e)
                client.close()
                return jsonify({'message':'Could not update username. Try again later', 'status':'not ok'})
        else:
            client.close()
            return jsonify({'message':'Incorrect password. Try again', 'status':'not ok'})
    else:
        client.close()
        return jsonify({'message':"Account with this username doesn't exist", 'status':'not ok'})
    

@app.route('/change_password', methods=['POST'])
def change_password():
    old_password = request.form.get('old_password')    
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    username = request.form.get('username')

    client = pymongo.MongoClient(url)
    db = client["xtracker"]
    xtracker_users = db['xtracker_users']

    user_record = xtracker_users.find_one({'username':username})
    if user_record:
        stored_password = user_record['password']
        if check_password_hash(stored_password, old_password):
            if new_password == confirm_password:
                hashed_password = generate_password_hash(new_password)
                try:
                    query = {'username': username}
                    update = {'$set': {'password': hashed_password}}  
                    xtracker_users.update_one(query, update)
                    client.close()
                    return jsonify({'message':'Password successfully changed!','status':'ok'})
                except Exception as e:
                    print(e)
                    client.close()
                    return jsonify({'message':'Could not change password. Try again later!', 'status': 'not ok'})
            else:
                client.close()
                return jsonify({'message':'Passwords do not match!', 'status': 'not ok'})    
        else:
            client.close()
            return jsonify({'message':'Incorrect password. Try again!', 'status': 'not ok'})
    else:
        client.close()
        return jsonify({'message':'Could not find any account with this username', 'status': 'not ok'})    


@app.route('/get_info_books')
def get_info_books():
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge"]
    fs = GridFS(db)
    categories = ['Computer science', "Childrens' books", 'Physics', 'Chemistry','Arts','Music','Religion']
    category_list = []
    for category in categories:
        sum = 0
        pdf_count = fs.find({'category':category})
        for item in pdf_count:
            sum += 1 
        object = {}
        object["category"] = category
        object["count"] = sum
        category_list.append(object)

    client.close()
    return jsonify({'category_count': category_list})


@app.route('/send_mail', methods=['POST'])
def send_mail():
    email = request.form.get('email')
    subject = request.form.get('subject')
    email_body = request.form.get('body')

    msg = Message(subject, sender='karenzijoslyn@gmail.com', recipients=[email])
    msg.body = email_body
    try:
        mail.send(msg)
        return jsonify({'message':'Email sent successfully', 'status':'ok'})
    except Exception as e:
        print(e)
        return jsonify({'message':'Could not send Email. Check your internet connection!', 'status':'not ok'})


@app.route('/like',methods=['POST'])
def like():
    try:
        user_id = request.form.get('user_id')
        post_id = request.form.get('post_id')

        client = pymongo.MongoClient(url)
        db = client["knowledgebridge_community_questions"]
        post_likes = db["post_likes"]

        like_status = list(post_likes.find({'user_id':user_id, 'post_id':post_id}))
        if like_status:
            post_likes.delete_many({'user_id':user_id, 'post_id':post_id})
        else:    
            data = {'user_id':user_id,'post_id':post_id, 'likes':1}  
            post_likes.insert_one(data)
            
        sum = post_likes.count_documents({'post_id':post_id})

        db = client["knowledgebridge_community_questions"]
        posts = db["posts"]

        update = {'$set': {'likes':sum }}  
        posts.update_one({'_id':ObjectId(post_id)}, update)


        return jsonify({'likes':sum,'status': 'ok'})
    except Exception as e:
        print(e)
        return jsonify({'status':'not ok'})
        

@app.route('/dislike',methods=['POST'])
def dislike():
    try:
        user_id = request.form.get('user_id')
        post_id = request.form.get('post_id')

        client = pymongo.MongoClient(url)
        db = client["knowledgebridge_community_questions"]
        post_dislikes = db["post_dislikes"]

        dislike_status = list(post_dislikes.find({'user_id':user_id, 'post_id':post_id}))
        if dislike_status:
            q = post_dislikes.delete_many({'user_id':user_id, 'post_id':post_id})
        else:    
            data = {'user_id':user_id,'post_id':post_id, 'likes':1}  
            post_dislikes.insert_one(data)

        sum = post_dislikes.count_documents({'post_id':post_id})

        db = client["knowledgebridge_community_questions"]
        posts = db["posts"]

        update = {'$set': {'dislikes':sum }}  
        posts.update_one({'_id':ObjectId(post_id)}, update)

        client.close()
        return jsonify({'dislikes':sum,'status': 'ok'})
    except Exception as e:
        print(e)
        client.close()
        return jsonify({'status':'not ok'})
    

@app.route('/add_answer', methods=['POST'])
def add_answer():
    try:
        user_id = request.form.get('user_id')
        question_id = request.form.get('question_id')
        answer = request.form.get('answer')
        question = request.form.get('question')
        timestamp = datetime.datetime.fromisoformat(request.form.get('timestamp'))

        client = pymongo.MongoClient(url)
        db = client["knowledgebridge_community_questions"]
        answers = db["answers"]

        data = { 'user_id':user_id, 'question_id':question_id, 'question':question, 'answer':answer, 'created_at':timestamp }
        answers.insert_one(data)

        client.close()
        return jsonify({'message':'Successful','status':'ok'})
    except Exception as e:
        print(e)
        client.close()
        return jsonify({'message':'Unsuccessful','status':'not ok'})


@app.route('/get_answers/<string:id>')
def get_answers(id):
    try:
        client = pymongo.MongoClient(url)
        db = client["knowledgebridge_community_questions"]
        questions = db["questions"]

        question_old = questions.find_one({'_id':ObjectId(id)})
        question = {
            'question_id': str(question_old.get('_id')),
            'created_at': str(question_old.get('created_at')),
            'question': question_old.get('question'),
        }

        db = client["knowledgebridge_community_questions"]
        answers = db["answers"]

        number_answers = int(request.args.get('answers'))
        results = answers.find({'question_id':id}).skip(number_answers).limit(2).sort("created_at", -1)

        db = client["xtracker"]
        xtracker_users = db['xtracker_users']

        list_results = []
        for result in results:
            user_record = xtracker_users.find_one(ObjectId(result.get('user_id')))
            datetime_object = datetime.datetime.strptime(str(result.get('created_at')), '%Y-%m-%d %H:%M:%S.%f')
            formatted_date = datetime_object.strftime('%b %d, %I:%M%p')
            object = {
                'answer_id': str(result.get('_id')),
                'question_id': str(result.get('question_id')),
                'username': user_record.get('username'),
                'email': user_record.get('email'),
                'profile_url': user_record.get('profile_url'),
                'created_at': formatted_date,
                'answer': result.get('answer')
            }
            list_results.append(object)
        client.close()
        return jsonify({'answers':list_results,'question':question,'status':'ok'})  
    except Exception as e:
        print(e)
        client.close()
        return jsonify({'message':'error','status':'not ok'})  


@app.route("/add_comment", methods=['POST'])
def add_comment():
    try:
        user_id = request.form.get('user_id')
        post_id = request.form.get('post_id')
        comment = request.form.get('comment')
        timestamp = datetime.datetime.fromisoformat(request.form.get('timestamp'))

        client = pymongo.MongoClient(url)
        db = client["knowledgebridge_community_questions"]
        comments = db['comments']

        data = { 'user_id':user_id, 'post_id':post_id, 'comment':comment, 'created_at':timestamp }
        comments.insert_one(data)
        sum = comments.count_documents({'post_id':post_id})

        db = client["knowledgebridge_community_questions"]
        posts = db["posts"]

        update = {'$set': {'comments':sum }}
        posts.update_one({'_id':ObjectId(post_id)}, update)

        client.close()
        return jsonify({'message':'Successful', 'comments': sum, 'status':'ok'})
    except Exception as e:
        print(e)
        client.close()
        return jsonify({'message':'Unsuccessful','status':'not ok'})

    
@app.route('/get_comments/<string:id>')
def get_comments(id):
    try:
        client = pymongo.MongoClient(url)
        db = client["knowledgebridge_community_questions"]
        comments = db['comments']

        results = comments.find({'post_id':id}).sort("created_at", -1)

        db = client["xtracker"]
        xtracker_users = db['xtracker_users']

        list_results = []
        for result in results:
            user_record = xtracker_users.find_one(ObjectId(result.get('user_id')))
            datetime_object = datetime.datetime.strptime(str(result.get('created_at')), '%Y-%m-%d %H:%M:%S.%f')
            formatted_date = datetime_object.strftime('%b %d, %I:%M%p')

            object = {
                'comment_id': str(result.get('_id')),
                'post_id': str(result.get('post_id')),
                'username': user_record.get('username'),
                'email': user_record.get('email'),
                'profile_url': user_record.get('profile_url'),
                'created_at': formatted_date,
                'comment': result.get('comment')
            }
            list_results.append(object)
        client.close()
        return jsonify({'comments':list_results,'status':'ok'})  
    except Exception as e:
        print(e)
        client.close()
        return jsonify({'message':'error','status':'not ok'})  


@app.route('/delete_post/<string:id>', methods=['DELETE'])
def delete_post(id):
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_community_questions"]
    posts = db['posts']

    res = posts.delete_one({'_id':ObjectId(id)})
    if res.deleted_count == 1:
        db = client["knowledgebridge_community_questions"]
        comments = db['comments']

        comments.delete_many({'post_id':id})

        db = client["knowledgebridge_community_questions"]
        post_likes = db['post_likes']

        post_likes.delete_many({'post_id':id})

        db = client["knowledgebridge_community_questions"]
        post_dislikes = db['post_dislikes']

        post_dislikes.delete_many({'post_id':id})

        client.close()
        return jsonify({'message':'Post deleted successfully!','status': 'ok'})
    else:
        client.close()
        return jsonify({'message':'Something went wrong. Try again later!','status': 'not ok'})
    

@app.route('/delete_comment/<string:id>', methods=['DELETE'])
def delete_comment(id):
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_community_questions"]
    comments = db['comments']

    result = comments.find_one({'_id':ObjectId(id)})

    res = comments.delete_one({'_id':ObjectId(id)})
    if res.deleted_count == 1:
        sum = comments.count_documents({'post_id':result.get('post_id')})

        db = client["knowledgebridge_community_questions"]
        posts = db["posts"]

        update = {'$set': {'comments':sum }}
        posts.update_one({'_id':ObjectId(result.get('post_id'))}, update)
        client.close()
        return jsonify({'message':'Comment deleted successfully!','comments': sum,'status': 'ok'})
    else:
        client.close()
        return jsonify({'message':'Something went wrong. Try again later!','status': 'not ok'})    
        

@app.route('/delete_question/<string:id>', methods=['DELETE'])
def delete_question(id):
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_community_questions"]
    questions = db['questions']

    res = questions.delete_one({'_id':ObjectId(id)})
    if res.deleted_count == 1:
        db = client["knowledgebridge_community_questions"]
        answers = db['answers']

        answers.delete_many({'question_id':id})

        client.close()
        return jsonify({'message':'Question deleted successfully!','status': 'ok'})
    else:
        client.close()
        return jsonify({'message':'Something went wrong. Try again later!','status': 'not ok'})
    

@app.route('/delete_answer/<string:id>', methods=['DELETE'])
def delete_answer(id):
    client = pymongo.MongoClient(url)
    db = client["knowledgebridge_community_questions"]
    answers = db['answers']

    res = answers.delete_one({'_id':ObjectId(id)})
    if res.deleted_count == 1:
        client.close()
        return jsonify({'message':'Answer deleted successfully!','status': 'ok'})
    else:
        client.close()
        return jsonify({'message':'Something went wrong. Try again later!','status': 'not ok'})    
    

@app.route('/elevate_privileges', methods=['POST'])
def elevate_privileges():
    id = request.form.get('id')

    client = pymongo.MongoClient(url)
    db = client["xtracker"]
    xtracker_users = db['xtracker_users']

    query = {'_id':ObjectId(id)}
    update = {'$set':{'admin':True}}

    result = xtracker_users.find_one(query)
    if result.get('admin'):
        client.close()
        return jsonify({'message':'Already an admin!','status': 'not ok'})

    try:
        xtracker_users.update_one(query, update)
        client.close()
        return jsonify({'message':'Privilege elevation successful!','status': 'ok'})
    except Exception as e:
        print(e)
        client.close()
        return jsonify({'message':'Privilege elevation unsuccessful. Try again later!','status': 'not ok'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)