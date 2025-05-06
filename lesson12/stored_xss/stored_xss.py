import os
from flask import Flask, request, render_template_string, abort

app = Flask(__name__)

# Create a 'comments' directory if it doesn't exist
COMMENT_FOLDER = 'comments'
os.makedirs(COMMENT_FOLDER, exist_ok=True)

# Configure the comment folder
app.config['COMMENT_FOLDER'] = COMMENT_FOLDER

@app.route('/')
def home():
    return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" comment="width=device-width, initial-scale=1.0">
            <title>Comment File</title>
        </head>
        <body>
            <h1>Message Board</h1>
            <form action="/create" method="post">
                <input type="text" name="comment" placeholder="Enter your comment here" required>
                <input type="submit" value="Create File">
            </form>
            <h2>Available Actions</h2>
            <ul>
                <li><a href="/comments">View Commented Files</a></li>
            </ul>
        </body>
        </html>
    '''

@app.route('/create', methods=['POST'])
def create_file():
    comment = request.form['comment']

    # Count existing files in the comments directory
    existing_files = os.listdir(app.config['COMMENT_FOLDER'])
    n = len(existing_files) + 1

    # Create the new filename
    filename = f'comment{n}'
    filepath = os.path.join(app.config['COMMENT_FOLDER'], filename)

    # Save the content to a new file
    with open(filepath, 'w') as f:
        f.write(comment)

    return f'File "{filename}" created successfully!'

@app.route('/comments', methods=['GET'])
def load_files():
    # Get all files in the comments directory
    files = os.listdir(app.config['COMMENT_FOLDER'])
    if not files:
        return 'No files available', 404

    files.sort()

    comment_sections = []

    for filename in files:
        filepath = os.path.join(app.config['COMMENT_FOLDER'], filename)
        if os.path.isfile(filepath):
            with open(filepath, 'r') as f:
                file_comment = f.read()
            comment_sections.append((filename, file_comment))

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" comment="width=device-width, initial-scale=1.0">
            <title>Files Content</title>
        </head>
        <body>
            <h1>Commented Files Content</h1>
            {% for filename, comment in comment_sections %}
                <h2>File: {{ filename }}</h2>
                <pre>{{ comment | safe }}</pre>
            {% endfor %}
        </body>
        </html>
    ''', comment_sections=comment_sections)

if __name__ == '__main__':
    app.run(debug=True, host="localhost", port=9000)
