from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import Flask, request, jsonify
from flask_httpauth import HTTPTokenAuth
import redis
import os

app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')
app.config['SECRET_KEY'] = os.urandom(24)


@app.route('/api/generate_token', methods=['GET'])
def generate_auth_token(expiration=600):
    if request.method == 'GET':
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        dicts = {'aaaa': 'bbbb', "cccccc": "dddddd", "eeeee": "fffff", "wwww": 'ccxcxcxxccxcxcxcxcxcx.com',
                 'aaaawwwexsdsd': 'ytyrtyry'}
        save_redis(s.dumps(dicts), s.dumps(dicts))
        return s.dumps(dicts)


@app.route('/api/token_to_id', methods=['POST'])
@auth.login_required
def verify_auth_token():
    s = Serializer(app.config['SECRET_KEY'])
    token = request.json.get('token')
    try:
        data = s.loads(token)
    except Exception as e:
        print(e)
        if str(e).find('Signature expired') != -1:
            return 'token timeout'
        else:
            return 'error'
    return jsonify(data)


@auth.verify_token
def verify_token(token):
    if select_redis(token) is not None:
        return True
    else:
        return False


def save_redis(key, value):
    r = redis.Redis(host='127.0.0.1', port=6379, db=0)
    r.set(key, value)
    r.setex(key, value, 600)


def select_redis(key):
    r = redis.Redis(host='127.0.0.1', port=6379, db=0)
    return r.get(key)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
