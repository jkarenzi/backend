
try:
        user_id = request.args.get('user_id')
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
        logging.info(f"User with id -{user_id} successfully downloaded book -{file.filename}")
        return response
    except Exception as e:
        print(e)
        client.close()
        return 'Error',500















try:
        user_id = request.args.get('user_id')
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
        logging.info(f"User with id -{user_id} successfully downloaded book -{file.filename}")
        return response
    except Exception as e:
        print(e)
        client.close()
        return 'Error',500


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
       logging.info(f"Admin {auth_res.get('username')} successfully deleted user with id -{id}")
       return jsonify({'msg': 'User deleted successfully','code':0})
        
    else:
        return jsonify({'msg': 'User not found','code':0})
