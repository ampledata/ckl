#!/usr/bin/env python
"""Flask ckl serverside endpoint/webapp.


Usage:
    1. Install Flask & Werkzeug Modules:
        $ pip install flask
        $ pip install merkzeug
    2. Start webapp:
        $ python flask_ckl.cgi
    3. Configure ckl to use webapp via /etc/cloudkick.conf:
        ckl_endpoint http://127.0.0.1:5000
        secret my-secret
    4. Use ckl client:
        $ ckl

More Info:
    https://github.com/ampledata/ckl

Derived from Cloudkick's ckl.cgi.
"""
__author__ = 'Greg Albrecht <gba@splunk.com>'
__copyright__ = 'Copyright 2012 Cloudkick, Inc.'
__license__ 'Apache License 2.0'


import cgi
import sqlite3
import sys
import time
import traceback

import flask
import werkzeug


#### BEGIN USER MODIFICATIONS

# Secret key used to authenticate clients for write permissions
SECRET_KEY = 'my-secret'

# Path to SQlite Database for this instance.
DATABASE_PATH = '.ckl.db'

#### END USER MODIFICATIONS


APP = flask.Flask(__name__)


def get_conn():
    _SQL_CREATE = ["""
      CREATE TABLE IF NOT EXISTS
        events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp NUMERIC NOT NULL,
          hostname VARCHAR(256) NOT NULL,
          remote_ip VARCHAR(256) NOT NULL,
          username VARCHAR(256) NOT NULL,
          message TEXT NOT NULL,
          script TEXT);
      """,
      """
      CREATE INDEX IF NOT EXISTS
        ix_events_hostname ON events (hostname);
      """]
    conn = sqlite3.connect(DATABASE_PATH)
    for q in _SQL_CREATE:
      conn.execute(q);
    conn.commit();
    return conn


@APP.route('/', methods=['POST'])
def process_post():
    if flask.request.form['secret'] != SECRET_KEY:
        abort(401)

    remote_ip = flask.request.environ['REMOTE_ADDR']
    script = flask.request.files.get('scriptlog', '')

    hostname = flask.request.form.get('hostname', '')
    msg = flask.request.form.get('msg', '')
    ts = flask.request.form.get('ts', 0)
    username = flask.request.form.get('username', '')

    if script:
        f_name = werkzeug.secure_filename(script.filename)
        script.save(f_name)
        script = open(f_name).read()

    c = get_conn()
    c.execute(
        """INSERT INTO events VALUES (NULL, ?, ?, ?, ?, ?, ?)""",
        [ts, hostname, remote_ip, username, msg, script])
    c.commit()

    return 'saved\n'


@APP.route('/list', methods=['POST'])
def process_list():
    if flask.request.form['secret'] != SECRET_KEY:
        abort(401)

    output = ''
    id = 0

    hostname = flask.request.form['hostname']
    count = int(flask.request.form.get('count', 5))

    c = get_conn().cursor()
    c.execute(
        'SELECT timestamp,hostname,username,message FROM events WHERE '
        'hostname = ? ORDER BY id DESC LIMIT ?', [hostname, count])

    for row in c:
        id =+ 1
        (timestamp, hostname, username, message) = row
        t = time.gmtime(timestamp)
        fmt_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", t)
        out_row = (
            "(%d) %s by %s on %s\n    %s"
            % (id, fmt_time, username, hostname, message))
        output = '\n'.join((output, out_row))
    return output


@APP.route('/detail', methods=['POST'])
def process_detail():
    if flask.request.form['secret'] != SECRET_KEY:
        abort(401)

    output = ''
    hostname = flask.request.form.get('hostname', '')
    id = int(flask.request.form.get('id', 1))

    c = get_conn().cursor()
    c.execute(
        'SELECT timestamp,hostname,username,message,script FROM events '
        'WHERE hostname = ? ORDER BY id DESC LIMIT 1 OFFSET ?',
        [hostname, id-1])

    for row in c:
        (timestamp, hostname, username, message, script) = row
        t = time.gmtime(timestamp)
        fmt_time = time.strftime('%Y-%m-%d %H:%M:%S UTC', t)
        out_row = (
            "(%d) %s by %s on %s\n    %s\n%s"
            % (id, fmt_time, username, hostname, message, script))
        output = '\n'.join((output, out_row))

    return output


@APP.route('/', methods=['GET'])
def mainAPP():
    id = 0
    c = get_conn().cursor()
    s = flask.request.form.get('hostname')
    if s is not None:
        c.execute(
            'SELECT timestamp,hostname,username,message,script FROM events '
            'WHERE hostname = ? ORDER BY id DESC LIMIT 500', [s])
    else:
        c.execute(
            'SELECT timestamp,hostname,username,message,script FROM events '
            'ORDER BY id DESC LIMIT 500')
        s = 'all servers'
    output = "<h1>server changelog for %s:</h1>" % s
    js = """
    <script type='text/javascript'>
      function unhide(id) {
        document.getElementById('script_'+ id).style.display = 'inline';
      }
    </script>"""
    output = '\n'.join((output, js))
    cserv = get_conn().cursor()
    cserv.execute('SELECT DISTINCT hostname FROM events ORDER BY hostname')

    form = "<form method='GET'><p>Hosts: <select name='hostname'>"
    formopt1 = "<option value=''>--all--</option>"
    output = '\n'.join((output, form))
    output = '\n'.join((output, formopt1))

    for row in cserv:
        formopt2 = "<option value='%s'>%s</option>" % (row[0], row[0])
        output = '\n'.join((output, formopt2))
    endform = "</select><input type='submit' value='Go'></p></form>"
    output = '\n'.join((output, endform))

    for row in c:
        id =+ 1
        (timestamp, hostname, username, message, script) = row
        t = time.gmtime(timestamp)
        fmt_time = time.strftime('%Y-%m-%d %H:%M:%S UTC', t)
        out_row = (
            "<hr><code>%s by %s on <a href='?hostname=%s'>%s</a></code>"
            "<br/><pre>  %s</pre>"
            % (fmt_time, username, hostname, hostname, message))
        output = '\n'.join((output, out_row))

        if script is not None and len(script):
            script_js = (
                "<a href='javascript:unhide(%d)'>script log available</a>"
                % id)
            script_out = (
                "<br><textarea style='display: none' id='script_%d' rows='15' "
                "cols='100'>%s</textarea>" % (id, script))
            output = '\n'.join((output, script_js))
            output = '\n'.join((output, script_out))

    return output


if __name__ == '__main__':
    APP.run(debug=True)
