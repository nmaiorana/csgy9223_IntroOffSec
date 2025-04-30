from flask import Flask, render_template_string

app = Flask(__name__)

template = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flask App with External JS</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            console.log("jQuery has been loaded successfully!");
            $("body").append("<p>Hello, Flask with jQuery!</p>");
        });
    </script>
</head>
<body>
    <h1>Welcome to My Flask App</h1>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True, port=9000)
