from flask import Flask, redirect, url_for, session, render_template, request
from requests_oauthlib import OAuth2Session
from datetime import datetime
import os
import secrets
from urllib.parse import urlencode

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # 生产环境建议使用固定密钥
app.config["SERVER_NAME"] = "localhost:5010"  # 本地开发配置

# SSO配置参数
CLIENT_ID = "1746716309210222592"
CLIENT_SECRET = "fa924d1252514b7f806cc4f0df2bfa5c"
SSO_BASE_URL = "http://103.218.240.13:30627/sso"
REDIRECT_URI = "http://localhost:5010/callback"

# SSO接口端点
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
    #sso = OAuth2Session(
    #    CLIENT_ID,
    #    redirect_uri=REDIRECT_URI,
    #    scope=["openid", "profile"]
    #)
    sso = OAuth2Session(
        client_id=CLIENT_ID,
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

        sso = OAuth2Session(
            client_id=CLIENT_ID,
            state=session['oauth_state'],
            redirect_uri=REDIRECT_URI
        )
        
        code=request.args.get('code')
        print(code)
        params = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
        # 获取访问令牌
        # token = sso.fetch_token(
        #     TOKEN_URL,
        #     method='GET',
        #     client_secret=CLIENT_SECRET,
        #     code=request.args.get('code'),
        #     params={
        #         'grant_type': 'authorization_code',
        #         'client_id': CLIENT_ID,
        #     }
        #    code=request.args.get('code'),
        #    ssoLogoutCall=f"{REDIRECT_URI}/logout",
        #    client_id=CLIENT_ID,
        # )
        get_token_url=f"{TOKEN_URL}?{urlencode(params)}"
        response = sso.get(get_token_url)
        body = response.json()
        token = body['data']
        print(token)
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

# 静态页面模板示例（需在templates目录创建）
"""
<!-- welcome.html -->
<h1>欢迎 {{ user.access_token|truncate(10) }} 用户！</h1>
<p>令牌有效期至：{{ user.expires_in }}</p>

<!-- error.html -->
<h1>登录失败</h1>
<p>错误原因：{{ error }}</p>
<a href="/">返回首页</a>
"""

if __name__ == '__main__':
    app.run(port=5010, debug=True)
