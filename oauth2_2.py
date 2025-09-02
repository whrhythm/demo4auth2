from flask import Flask, redirect, url_for, session, render_template, request, jsonify
from requests_oauthlib import OAuth2Session
from datetime import datetime
import os
import secrets
from urllib.parse import urlencode

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config["SERVER_NAME"] = "192.168.20.122:5010"

# SSO 接口端点配置（常量部分）
SSO_BASE_URL = "http://192.168.20.122:31240/sso"
REDIRECT_URI = "http://192.168.20.122:5010/callback"
AUTHORIZATION_URL = f"{SSO_BASE_URL}/oauth2/authorize"
TOKEN_URL = f"{SSO_BASE_URL}/oauth2/token"
REVOKE_URL = f"{SSO_BASE_URL}/oauth2/revoke"
REFRESH_URL = f"{SSO_BASE_URL}/oauth2/refresh"

@app.route('/')
def home():
    if 'oauth_token' in session:
        return render_template('welcome.html', user=session.get('user'))
    return '<a href="/login">使用SSO登录</a>'

@app.route('/login')
def login():
    """启动OAuth授权流程"""
    # 从请求参数获取client_id和client_secret
    client_id = request.args.get('client_id')
    client_secret = request.args.get('client_secret')
    
    if not client_id or not client_secret:
        return jsonify({"error": "client_id和client_secret参数必填"}), 400
    
    # 将client_id存入session供callback使用
    session['client_id'] = client_id
    session['client_secret'] = client_secret
    
    sso = OAuth2Session(
        client_id=client_id,
        redirect_uri=REDIRECT_URI
    )
    
    auth_url, state = sso.authorization_url(
        AUTHORIZATION_URL,
        access_type="offline",
        prompt="select_account"
    )
    session['oauth_state'] = state
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """处理授权回调"""
    try:
        # 验证state参数防止CSRF攻击
        if request.args.get('state') != session.get('oauth_state'):
            return redirect(url_for('error', msg="无效的会话状态"))

        # 从session获取client_id和client_secret
        client_id = session.get('client_id')
        client_secret = session.get('client_secret')
        
        if not client_id or not client_secret:
            return redirect(url_for('error', msg="缺少客户端凭证"))

        sso = OAuth2Session(
            client_id=client_id,
            state=session['oauth_state'],
            redirect_uri=REDIRECT_URI
        )

        code = request.args.get('code')
        params = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret
        }
        
        get_token_url = f"{TOKEN_URL}?{urlencode(params)}"
        response = sso.get(get_token_url)
        body = response.json()
        token = body['data']

        # 存储令牌和用户信息
        session['oauth_token'] = token
        session['user'] = {
            'access_token': token['access_token'],
            'refresh_token': token.get('refresh_token'),
            'expires_in': token['expires_in']
        }
        return redirect(url_for('home'))

    except Exception as e:
        return redirect(url_for('error', msg=str(e)))

@app.route('/error')
def error():
    """错误显示页面"""
    error_msg = request.args.get('msg', '未知错误')
    return render_template('error.html', error=error_msg)

if __name__ == '__main__':
    app.run(port=5010, debug=True)
