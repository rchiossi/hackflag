import sqlite3

from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash

from contextlib import closing

# configuration
DATABASE = '/home/rchiossi/hackflag.db'
DEBUG = True
SECRET_KEY = 'super_secret_key'
ADMIN = u'admin'
ADMINPASS = u'omgpassword'

# Initialize application
app = Flask(__name__)
app.config.from_object(__name__)

def connect_db():
    return sqlite3.connect(app.config['DATABASE'])

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()

        db.execute('insert into users (name, password, type) values (?, ?, ?)',
                   [app.config['ADMIN'],app.config['ADMINPASS'],u'admin'])
        db.commit()

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    g.db.close()

@app.route('/')
def scoreboard():
    query = g.db.execute('select name from users where type=?',(u'user',))
    users = [{'name':row[0]} for row in query.fetchall()]
    
    query = g.db.execute('select name,description,points from flags')
    flags = [{'name':row[0],'description':row[1],'points':row[2]}
             for row in query.fetchall()]

    for user in users:
        user['points'] = 0

        query = g.db.execute('select flag from scoreboard where user=?',
                             (user['name'] ,))
        user['flags'] = [row[0] for row in query.fetchall()]

        for flag in flags:
            if flag['name'] in user['flags']:
                user['points'] = user['points'] + flag['points']

    return render_template('scoreboard.html', users=users, flags=flags)

@app.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('logged_in') or not session.get('admin_session'):
        abort(401)

    username = request.form['username']
    password = request.form['password']
    usertype = request.form['type']

    g.db.execute('insert into users (name, password, type) values (?, ?, ?)',
                 [username,password,usertype])
    g.db.commit()

    flash('New user added.')
    return redirect(url_for('admin'))

@app.route('/add_flag', methods=['POST'])
def add_flag():
    if not session.get('logged_in') or not session.get('admin_session'):
        abort(401)

    name = request.form['name']
    value = request.form['value']
    points = request.form['points']
    description = request.form['description']    

    g.db.execute('insert into flags (value,name,points,description) values (?, ?, ?, ?)',
                 [value,name,points,description])
    g.db.commit()

    flash('New flag added.')
    return redirect(url_for('admin'))


@app.route('/get_flag', methods=['POST'])
def get_flag():
    if not session.get('logged_in'):
        abort(401)

    username = session.get('username')

    flag = request.form['flag']

    query = g.db.execute('select name, value from flags')
    flags = {row[0]:row[1] for row in query.fetchall()}

    for key in flags.keys():
        if flags[key] == flag:
            g.db.execute('insert into scoreboard (user, flag) values (?, ?)',[username,key])
            g.db.commit()
            flash('You got the flag for %s.' % key)
            return redirect(url_for('scoreboard')) 

    flash('Invalid flag.')

    return redirect(url_for('scoreboard')) 

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        query = g.db.execute('select name, password, type from users')
        users = [{'name':row[0],'password':row[1],'type':row[2]} for row in query.fetchall()]

        username = request.form['username']
        password = request.form['password']

        for user in users:
            if str(username) != str(user['name']): continue

            if str(user['password']) != str(password): break

            session['logged_in'] = True
            session['username'] = username

            if user['type'] == u'admin':
                session['admin_session'] = True

            flash('You are logged in as %s' % username)

            return redirect(url_for('scoreboard')) 

        error = 'Invalid username or password.'

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('admin_session', None)

    flash('You were logged out')

    return redirect(url_for('scoreboard'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('admin_session'):
        abort(401)

    return render_template('admin.html')

@app.route('/register', methods=['POST','GET'])
def register():
    error = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        query = g.db.execute('select name from users')
        users = [row[0] for row in query.fetchall()]
        
        if not username in users:
            g.db.execute('insert into users (name, password, type) values (?, ?, ?)',
                     [username,password,u'user'])
            g.db.commit()

            flash('User %s registered.' % username)
            return redirect(url_for('scoreboard'))
        else:
            error = 'User already exists'

    return render_template('register.html', error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
