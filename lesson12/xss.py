from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/vulnerable')
def greet():
    name = request.args.get('name', 'Guest')
    return f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Greeting Page</title>
        </head>
        <body>
            <h1>Hello, {name}!</h1>
        </body>
        </html>
    '''

if __name__ == '__main__':
    app.run(debug=True, port=9000)
