from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import os
import json
import pyshark

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key

# Configure upload and converted folders
UPLOAD_FOLDER = './uploads'
CONVERTED_FOLDER = './converted_json'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['CONVERTED_FOLDER'] = CONVERTED_FOLDER

# Ensure the folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CONVERTED_FOLDER, exist_ok=True)

@app.route('/')
def upload_form():
    return render_template('upload.html')

@app.route('/', methods=['POST'])
def upload_file():
    username = request.form['username']
    file = request.files['file']

    if file and file.filename.endswith('.pcap'):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Convert PCAP to JSON
        json_filename = f"{username}_{file.filename.replace('.pcap', '.json')}"
        json_filepath = os.path.join(app.config['CONVERTED_FOLDER'], json_filename)

        try:
            # Convert file synchronously on the main thread
            convert_pcap_to_json(file_path, json_filepath)
            flash('File uploaded and converted successfully', 'success')
        except Exception as e:
            flash(f'Error during conversion: {e}', 'error')
            return redirect(url_for('upload_form'))

        session['success_message'] = 'File uploaded and converted successfully'
        session['selected_file'] = json_filename
        return redirect(url_for('view_files'))

    flash('Invalid file type, only .pcap files are allowed', 'error')
    return redirect(url_for('upload_form'))

@app.route('/view_files', methods=['GET', 'POST'])
def view_files():
    converted_files = [
        file for file in os.listdir(app.config['CONVERTED_FOLDER']) if file.endswith('.json')
    ]

    if request.method == 'POST':
        selected_file = request.form.get('selected_file')
        session['selected_file'] = selected_file
        return redirect(url_for('search_results', filename=selected_file))

    return render_template('view_files.html', files=converted_files)

@app.route('/search_results/<filename>')
def search_results(filename):
    file_path = os.path.join(app.config['CONVERTED_FOLDER'], filename)

    if not os.path.exists(file_path):
        flash('File not found!', 'error')
        return redirect(url_for('view_files'))

    with open(file_path) as f:
        file_data = json.load(f)

    # Retrieve template_name from session or set a default
    template_name = session.get('template_name', f"Template_{filename}")
    session['template_name'] = template_name

    return render_template('search_results.html', filename=filename, json_data=file_data, template_name=template_name)


@app.route('/api/search_keys', methods=['GET'])
def search_keys():
    query = request.args.get('q', '').lower()
    filename = session.get('selected_file')
    file_path = os.path.join(app.config['CONVERTED_FOLDER'], filename)

    if not os.path.exists(file_path):
        return jsonify([])

    with open(file_path) as f:
        file_data = json.load(f)

    suggestions = search_json(file_data, query)
    return jsonify(suggestions)

@app.route('/api/search_suggestions', methods=['GET'])
def search_suggestions():
    query = request.args.get('q', '').lower()
    files = [file for file in os.listdir(app.config['CONVERTED_FOLDER']) if file.endswith('.json')]

    suggestions = []
    for file in files:
        if query in file.lower():
            suggestions.append({"filename": file})

    return jsonify(suggestions)

def search_json(data, query):
    matches = []
    if isinstance(data, dict):
        for key, value in data.items():
            if query in key.lower():
                matches.append({"key": key, "value": value})
            if isinstance(value, (dict, list)):
                matches.extend(search_json(value, query))
    elif isinstance(data, list):
        for item in data:
            matches.extend(search_json(item, query))
    return matches

def convert_pcap_to_json(input_pcap_path, output_json_path):
    """Convert a PCAP file to a JSON file using PyShark."""
    packets = pyshark.FileCapture(input_pcap_path)
    data = []

    # Extract packet details
    for packet in packets:
        packet_dict = {}
        for layer in packet.layers:
            packet_dict[layer.layer_name] = layer._all_fields
        data.append(packet_dict)

    with open(output_json_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)

    packets.close()

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.before_request
def initialize_session():
    if 'validated_pairs' not in session:
        session['validated_pairs'] = []
    else:
        try:
            session['validated_pairs'] = json.loads(json.dumps(session['validated_pairs']))
        except json.JSONDecodeError:
            session['validated_pairs'] = []

@app.route('/validate', methods=['GET'])
def validate():
    key = request.args.get('key')
    value = request.args.get('value')
    session['validated_pairs'] = session.get('validated_pairs', []) + [{'key': key, 'value': value}]
    app.logger.debug(f"Validated pairs: {session['validated_pairs']}")
    return render_template('Validate.html', key=key, value=value)


@app.route('/delete', methods=['POST'])
def delete_entry():
    if 'selected_pairs' in session:
        selected_pairs = session['selected_pairs']
        index = int(request.form.get('index')) - 1  # Convert index to 0-based
        if 0 <= index < len(selected_pairs):
            del selected_pairs[index]
            session['selected_pairs'] = selected_pairs  # Save back to session
            flash('Pair deleted successfully!', 'success')
        else:
            flash('Invalid index!', 'error')

    return redirect(url_for('validate'))

@app.route('/template_structure', methods=['GET', 'POST'])
def template_structure():
    templates_folder = './templates_storage'
    os.makedirs(templates_folder, exist_ok=True)

    if request.method == 'POST':
        template_name = session.get('template_name')
        validated_pairs = session.get('validated_pairs', [])

        # Debugging: Check the session data
        app.logger.debug(f"Template Name: {template_name}")
        app.logger.debug(f"Validated Pairs: {validated_pairs}")

        if not template_name:
            flash('Template name is missing!', 'error')
            return redirect(url_for('template_structure'))

        if not validated_pairs:
            flash('No validated pairs found!', 'error')
            return redirect(url_for('template_structure'))

        # Save the template data
        template_data = {'name': template_name, 'data': validated_pairs}
        template_path = os.path.join(templates_folder, f'{template_name}.json')

        try:
            with open(template_path, 'w') as f:
                json.dump(template_data, f, indent=4)
            flash('Template saved successfully!', 'success')
            app.logger.debug(f"Template saved at {template_path}")
        except Exception as e:
            flash(f'Error saving template: {e}', 'error')
            app.logger.error(f"Error saving template: {e}")

    # Load templates for display
    templates = []
    for file_name in os.listdir(templates_folder):
        if file_name.endswith('.json'):
            try:
                with open(os.path.join(templates_folder, file_name)) as f:
                    templates.append(json.load(f))
            except json.JSONDecodeError:
                flash(f'Error loading template: {file_name}', 'error')

    return render_template('template_structure.html', templates=templates)


   
@app.route('/delete_template', methods=['POST'])
def delete_template():
    template_name = request.form.get('template_name')
    template_folder = './templates_storage'
    templates = []
    for file_name in os.listdir(template_folder):
        if file_name.endswith('.json'):
            try:
                with open(os.path.join(template_folder, file_name)) as f:
                    templates.append(json.load(f))
            except json.JSONDecodeError:
                flash(f'Error loading template: {file_name}', 'error')

    templates = [t for t in templates if t['name'] != template_name]
    flash('Template deleted successfully!', 'success')
    return redirect(url_for('template_structure'))

@app.route('/templates', methods=['GET'])
def get_templates():
    return jsonify(templates)

@app.route('/save_test', methods=['GET', 'POST'])
def save_test():
    if request.method == 'POST':
        template_data = {'name': 'Test Template', 'data': [{'key': 'testKey', 'value': 'testValue'}]}
        template_path = './templates_storage/Test_Template.json'
        try:
            with open(template_path, 'w') as f:
                json.dump(template_data, f, indent=4)
            flash('Test template saved successfully!', 'success')
        except Exception as e:
            flash(f'Error saving test template: {e}', 'error')
        return redirect(url_for('template_structure'))
    
    return render_template('template_structure.html')


#   @app.route('/save_test', methods=['GET', 'POST'])
# def save_test():
#     print("Save Test Route Triggered")  # Debug line to confirm route is accessed
#     if request.method == 'POST':
#         template_data = {'name': 'Test Template', 'data': [{'key': 'testKey', 'value': 'testValue'}]}
        
#         # Full absolute path
#         template_path = os.path.abspath('./templates_storage/Test_Template.json')
#         print(f"Saving template at: {template_path}")
        
#         try:
#             with open(template_path, 'w') as f:
#                 json.dump(template_data, f, indent=4)
#             flash('Test template saved successfully!', 'success')
#         except Exception as e:
#             flash(f'Error saving test template: {e}', 'error')
        
#         return redirect(url_for('template_structure'))
    
#     return render_template('template_structure.html')


if __name__ == '__main__':
    app.run(debug=True)
