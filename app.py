# import the Flask class from the flask module
import json
import logging
import binascii
from re import S
logging.basicConfig(
    format='%(process)d- %(lineno)d - %(levelname)s-%(message)s',level=logging.INFO)
import srp
import urllib.request as ur
import sqlite3
# import numpy as np



from flask import Flask, render_template , request, session

# create the application object
app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

# use decorators to link the function to a url
@app.route('/')
def home():
    return "Hello, World!"  # return a string

@app.route('/index')
def welcome():
    return render_template('index.html')  # render a template

@app.route('/login',methods=['GET', 'POST'])
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')  # render a template

@app.route('/save', methods=['POST'])
def saveUser():
    if request.form:
        dbconnection = sqlite3.connect('app.db')
        if(chk_conn(dbconnection)):
            username = request.form.get("username")
            salt = request.form.get("salt")
            verifier = hex(int(request.form.get("verifier")))
            logging.info("\n\n{} \n\n{} \n\n{}".format(username,salt,verifier))
            cur = dbconnection.cursor()
            cur.execute("INSERT INTO user (username, salt, verifier) VALUES (?, ?, ?)",
                        (username, salt,verifier)
                        )
            dbconnection.commit()
            dbconnection.close()
            return render_template('login.html')
        else:
            print("DB CONNECTION CLOSED")
            return render_template('register.html')

@app.route('/challange',methods=['POST'])
def challange():
    if request.form:
        username = request.form.get("username")
        a_hex = request.form.get("server_a")
        # print(username)
        # print(type(a_hex.encode('utf-8')))
        if request.method != 'POST' or username is None or a_hex is None:
            return json.dumps({'success':"Invalid Username in Request"}), 400, {'ContentType':'application/json'} 
        else:
            # class MyEncoder(json.JSONEncoder):
            #     def default(self, obj):
            #         if isinstance(obj, np.ndarray):
            #             return obj.tolist()
            #         elif isinstance(obj, bytes):
            #             return str(obj, encoding='utf-8')
            #         return json.JSONEncoder.default(self, obj)
            
            dbconnection = sqlite3.connect('app.db')
            cur = dbconnection.cursor()
            cur.execute("SELECT salt, verifier FROM user WHERE username = ?", (username,))
            row = cur.fetchone()
            salt, verifier = row
            dbconnection.close()
            
            
            print(f'\n a_hex --> {a_hex} \n verifier --> {verifier}\
                    \n salt --> {salt}')

            
            # print(f"A : {hex(int(a_hex, 2))}")
            # print(f"A : {bytes(a_hex, encoding='utf-8')}")
            # print(f"A : {a_hex.encode('utf-8')}")
            # print("Username : {}".format(username))
            # print("Salt : {}".format(salt))
            # print("Verifer : {}".format(verifier))
            
            
            safe_unhexlify = lambda x: binascii.unhexlify(x) if (len(x) % 2 == 0) else binascii.unhexlify('0' + x)

            verifier  = safe_unhexlify(verifier)
            a_hex = safe_unhexlify(a_hex)
            salt = safe_unhexlify(salt)

            print(f'\n a_hex --> {binascii.hexlify(a_hex)} \n verifier --> {binascii.hexlify(verifier)}\
                    \n salt --> {binascii.hexlify(salt)}')

            print(f'\n a_hex --> {a_hex} \n verifier --> {verifier}\
                    \n salt --> {salt}')

            svr = srp.Verifier( username, salt, verifier , a_hex, ng_type=0, bytes_b=bytes.fromhex('83241f299889746600fc6b94a8e6eb9fc6b55be168fcb1406bda4270d8d2b362') )
            s, B = svr.get_challenge()
            import pdb; pdb.set_trace()
            print(svr.b)
            # session_key = svr.get_session_key()
            # print(session_key)

            # session['session_key'] = session_key

            if s is None or B is None:
                logging.error ("Auth Failed.")
                return
            # logging.info("\nuname -> {}\nA -> {}".format(str(s.hex()),str(B.hex())))
            # logging.info("s : ", str(s.hex()))
            # logging.info("B hex: ", str(B.hex()))
            
            print(f'\n\n\n salt --> {type(salt)}\
                    \n\n\n verifier --> {type(verifier)}\
                    \n\n\n B --> {int.from_bytes(B, "big")}')
            
            return json.dumps({'salt': str(salt),'verifier': str(verifier), "B": str(int.from_bytes(B, "big"))}), 200, {'ContentType':'application/json'}

    else: 
        return json.dumps({'success':"No Request Data"}), 400, {'ContentType':'application/json'} 


@app.route('/authenticate',methods=['POST'])
def authenticate():
    if request.form:
        # import pdb; pdb.set_trace()
        username = request.form.get("username")
        creds = request.form.get('credentials')

        credentials = json.loads(creds)
        A = credentials.get('A')
        M1 = credentials.get('M1')
        
        print(M1)

        dbconnection = sqlite3.connect('app.db')
        cur = dbconnection.cursor()
        cur.execute("SELECT salt, verifier FROM user WHERE username = ?", (username,))
        row = cur.fetchone()
        salt, verifier = row
        dbconnection.close()
        # A = bytes.fromhex(A)
        
        
        safe_unhexlify = lambda x: binascii.unhexlify(x) if (len(x) % 2 == 0) else binascii.unhexlify('0' + x)

        verifier  = safe_unhexlify(verifier)
        A = bytes.fromhex(A)
        salt = safe_unhexlify(salt)
        
        import pdb; pdb.set_trace()
        
        svr = srp.Verifier( username, salt, verifier , A )
        HMAK = svr.verify_session(M1)

        if svr.authenticated():
            return "Welcome"

def chk_conn(conn):
     try:
        conn.cursor()
        return True
     except Exception as ex:
        return False
    
# start the server with the 'run()' method
if __name__ == '__main__':
    app.run(debug=True)
