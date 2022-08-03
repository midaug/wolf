const config = require('../../conf/config')
const RbacPub = require('./rbac-pub')
const RbacTokenError = require('../errors/rbac-token-error')
const UserModel = require('../model/user')
const ApplicationModel = require('../model/application')
const constant = require('../util/constant')
const util = require('../util/util')
const signUtil = require('../util/sign')
const userCache = require('../util/user-cache')
const {ldapOptions} = require('./helper')


const userFields = ['id', 'username', 'nickname', 'email', 'appIDs',
  'manager',  'lastLogin', 'profile', 'createTime', 'permissions', 'roles'];

const errors = {
  ERR_TIME_MISSING: 'Time missing!',
  ERR_SIGN_MISSING: 'Sign missing!',
  ERR_UKEY_MISSING: 'Ukey missing!',  
  ERR_TIME_CHECK_OUT: 'Check timeout!', 
  ERR_UKEY_NOT_FOUND: 'Ukey not found!',   
  ERR_SIGN_CHECK_ERROR: 'Sign verification failed!',     

  ERR_USERNAME_MISSING: 'Username missing!',
  ERR_PASSWORD_MISSING: 'Password missing!',
  ERR_APPID_NOT_FOUND: 'Appid not found!',
  ERR_USER_NOT_FOUND: 'User not found!',
  ERR_PASSWORD_ERROR: 'Password error!',
  ERR_APPID_MISSING: 'Appid missing!',
  ERR_PASSWORD_CHANGE_NOT_ALLOWED: 'Password change is not allowed',
  ERR_OLD_PASSWORD_REQUIRED: 'Old password is required',
  ERR_NEW_PASSWORD_REQUIRED: 'New password is required',
  ERR_REPEATED_PASSWORD_INCORRECT: 'The password you entered repeatedly is incorrect.',
  ERR_OLD_PASSWORD_INCORRECT: 'Old password is incorrect.',
  ERR_USER_DISABLED: 'User is disabled.',
  ERR_USER_APPIDS: 'User is not associated with the app.'
}

class Rbac extends RbacPub {
  constructor(ctx) {
    super(ctx, UserModel)
  }

  async _loginPageRender() {
    const returnTo = this.getArg('return_to', '/');
    const username = this.getArg('username');
    let error = this.getArg('error');
    const password = this.getArg('password');
    const appid = this.getArg('appid', '')
    let appname = ''
    if(appid) {
      const application = await ApplicationModel.findByPk(appid)
      if (!error && !application) {
        error = `application id '${appid}' not found`
      } else if(application) {
        appname = application.name
      }
    } else {
      error = `appid missing`
    }

    let authTypeDef = '1'
    let ldap = ldapOptions()
    if (ldap.supported) {
      authTypeDef = '2'
    }
    const authType = this.getArg('authType', authTypeDef)

    await this.ctx.render('login', {
      returnTo,
      username,
      password,
      error,
      appid,
      appname,
      ldap,
      authType,
    })
  }

  async loginHtml() {
    await this._loginPageRender();
  }

  async loginGet() {
    await this._loginPageRender();
  }

  async index() {
    this.ctx.status = 200;
    this.ctx.body = `wolf rbac index`
  }

  _getClientToken() {
    let token = this.ctx.request.headers['x-rbac-token']
    if (!token) {
      token = this.ctx.cookies.get('x-rbac-token')
    }
    return token
  }

  async _loginPostInternal() {
    const authType = this.getIntArg('authType', constant.AuthType.PASSWORD)
    if (constant.AuthType.USERSIGN != authType) {
      return await this._loginPostUserInternal()
    }
    const ukey = this.getArg('ukey')
    const sign = this.getArg('sign')
    const time = this.getRequiredIntArg('time')
    const appid = this.getArg('appid')
    const args = this.getArgs()
    this.log4js.debug('USERSIGN: %s', JSON.stringify(args))
    if (!sign) {
      return {ok: false, reason: 'ERR_SIGN_MISSING'}
    }
    if (!time) {
      return {ok: false, reason: 'ERR_TIME_MISSING'}
    }
    if (!ukey) {
      return {ok: false, reason: 'ERR_UKEY_MISSING'}
    }
    if (!appid) {
      return {ok: false, reason: 'ERR_APPID_MISSING'}
    }
    const diff_time = Math.abs(util.timestamp() - time)
    if (diff_time > config.rbacUserSignCheckTime){
      return {ok: false, reason: 'ERR_TIME_CHECK_OUT'}
    }
    const {userInfo, cached} = await userCache.getUserInfoByUkey(ukey, appid)
    if (!userInfo) {
      this.log4js.warn(`user ukey [%s] not found, cache is %s`, ukey, cached)
      return {ok: false, reason: 'ERR_UKEY_NOT_FOUND'}
    }
    
    // 插入sign认证逻辑 接收body：{"appid": "restful", "key":"xxxxxx", "time":"1658993772", "authType":3, "sign":"xxxxxxxxx"}，
    // body提取删除sign后字段排序生成url参数格式.   key+拼装参数+secret 计算出sign与传入的sign验证
    const usecret = userInfo['usecret']
    delete args.sign
    const encryptSign = signUtil.encrypt(ukey, usecret, args)
    if (sign !== encryptSign){
      this.log4js.warn(`%s encryptSign=%s`, errors.ERR_SIGN_CHECK_ERROR, encryptSign)
      return {ok: false, reason: 'ERR_SIGN_CHECK_ERROR'}
    }

    // const application = await ApplicationModel.findByPk(appid)
    // if (!application) { // app not exist
    //   this.log4js.warn(`application id [%s] not found`, username)
    //   return {ok: false, reason: 'ERR_APPID_NOT_FOUND'}
    // }
    if (!userInfo.appIDs || !userInfo.appIDs.includes(appid)) {
      this.log4js.warn('user [%s] login failed! user is not associated with the app', username)
      return {ok: false, reason: 'ERR_USER_APPIDS'}
    }

    // await userCache.flushUserCacheByID(ukey, appid)

    const { token, expiresIn } = await this.tokenCreateCheck(userInfo, appid)
    return {ok: true, token, expiresIn, userInfo}
  }

  async _loginPostUserInternal() {
    const username = this.getArg('username')
    const password = this.getArg('password')
    const returnTo = this.getArg('return_to', '/')
    const appid = this.getArg('appid')
    const authType = this.getIntArg('authType', constant.AuthType.PASSWORD)

    this.log4js.info('appid: %s, username %s login, return to url: %s', appid, username, returnTo)
    if (!username) {
      return {ok: false, reason: 'ERR_USERNAME_MISSING'}
    }

    if (!password) {
      return {ok: false, reason: 'ERR_PASSWORD_MISSING'}
    }

    if (!appid) {
      return {ok: false, reason: 'ERR_APPID_MISSING'}
    }

    const application = await ApplicationModel.findByPk(appid)
    if (!application) { // app not exist
      this.log4js.warn(`application id [%s] not found`, username)
      return {ok: false, reason: 'ERR_APPID_NOT_FOUND'}
    }
    const {userInfo, err: loginErr} = await this.userLoginInternal(username, password, {authType})
    if (loginErr) {
      return {ok: false, reason: loginErr}
    }

    if (!userInfo.appIDs || !userInfo.appIDs.includes(appid)) {
      this.log4js.warn('user [%s] login failed! user is not associated with the app', username)
      return {ok: false, reason: 'ERR_USER_APPIDS'}
    }

    await userCache.flushUserCacheByID(userInfo.id, appid)

    const { token, expiresIn } = await this.tokenCreate(userInfo, appid)
    return {ok: true, token, expiresIn, userInfo}
  }

  async loginPost() {
    const {ok, reason, token, userInfo, expiresIn} = await this._loginPostInternal();
    if (!ok) {
      this.fail(200, reason, {})
      return
    }
    const {id, username, nickname} = userInfo;
    const data = {userInfo: {id, username, nickname}, token, exp: expiresIn}
    this.success(data)
  }

  async loginRest() {
    await this.loginPost()
  }

  async loginSubmit() {
    const res = await this._loginPostInternal();
    if(!res.ok) {
      const error = errors[res.reason] || 'Login failed!'
      const args = Object.assign({}, this.args)
      args.error = error;
      delete(args["password"])
      const loginUrl = '/wolf/rbac/login?' + Object.keys(args).map(arg => `${arg}=${encodeURIComponent(args[arg])}`).join('&')
      this.ctx.redirect(loginUrl)
      return
    }

    const returnTo = this.getArg('return_to', '/')

    const maxAge = config.tokenExpireTime * 1000;
    this.ctx.cookies.set('x-rbac-token', res.token,
      {
        maxAge: maxAge,
        httpOnly: false,
        overwrite: false,
      }
    )
    this.ctx.status = 302;
    this.ctx.redirect(returnTo);
  }

  async accessCheck() {
    //got from the token or args.
    const appID = this.ctx.appid || this.getRequiredStringArg('appID');
    const action = this.getRequiredStringArg('action')
    const resName = this.getRequiredStringArg('resName')

    const userInfo = this.ctx.userInfo
    try {
      await this._accessCheckInternal(userInfo, appID, action, resName)
    } finally {
      try{
        this._writeAccessLog();
      }catch(err) {
        this.log4js.error('write access log failed! %s', err)
      }
    }
  }

  async noPermission() {
    const args = this.getArgs();
    this.log4js.info('---- no permission args: %s', JSON.stringify(args))
    await this.ctx.render('no_permission', args)
  }

  async noPermissionHtml() {
    await this.noPermission();
  }

  async logout() {
    const userInfo = this.ctx.userInfo;
    const token = this._getClientToken()
    await this.tokenDelete(token)
    this.log4js.info('-------- %s logout --------', JSON.stringify(userInfo))
    const maxAge = config.tokenExpireTime * 1000;
    this.ctx.cookies.set(
      'x-rbac-token', 'logouted',
      {
        maxAge: maxAge,
        httpOnly: false,
        overwrite: false,
      }
    )
    this.ctx.status = 302;
    const defaultReturnTo = '/wolf/rbac/login.html?appid=' + this.ctx.appid
    const returnTo = this.getArg('return_to', defaultReturnTo)
    this.ctx.redirect(returnTo);
  }

  async changePwdHtml() {
    const {username} = this.ctx.userInfo;
    const error = this.getArg('error', '')
    const success = null;
    const args = {username, error, success, oldPassword: undefined, newPassword: undefined, reNewPassword: undefined}
    await this.ctx.render('change_pwd.html', args)
  }

  async changePwdGet() {
    await this.changePwdHtml()
  }

  async _changePwdInternal(opts) {
    opts = opts || {}
    const args = this.getArgs();
    const {id: userId, username} = this.ctx.userInfo;
    args.username = username;
    if (!config.clientChangePassword) {
      return {ok: false, reason: 'ERR_PASSWORD_CHANGE_NOT_ALLOWED'}
    }

    const oldPassword = this.getArg('oldPassword')
    const newPassword = this.getArg('newPassword')
    if (!oldPassword) {
      return {ok: false, reason: 'ERR_OLD_PASSWORD_REQUIRED'}
    }
    if (!newPassword) {
      return {ok: false, reason: 'ERR_NEW_PASSWORD_REQUIRED'}
    }

    if (opts.checkReNewPassword) {
      const reNewPassword = this.getArg('reNewPassword')
      if (newPassword !== reNewPassword) {
        return {ok: false, reason: 'ERR_REPEATED_PASSWORD_INCORRECT'}
      }
    }

    const userInfo = await UserModel.findByPk(userId);
    if (!userInfo) {
      this.log4js.error('change password failed! userId:%d (from token) not found in database', userId)
      throw new RbacTokenError('TOKEN_USER_NOT_FOUND')
    }

    if (!util.comparePassword(oldPassword, userInfo.password)) {
      return {ok: false, reason: 'ERR_OLD_PASSWORD_INCORRECT'}
    }


    const options = {where: {id: userId}}
    const values = {password: util.encodePassword(newPassword), updateTime: util.unixtime()}
    await UserModel.mustUpdate(values, options)

    return {ok: true, userInfo}
  }

  async changePwdPost() {
    const {ok, reason} = await this._changePwdInternal();
    if (!ok) {
      const errmsg = errors[reason] || reason
      this.fail2(200, reason, errmsg, {})
      return
    }
    const data = {}
    this.success(data)
  }

  async changePwdSubmit() {
    const args = this.getArgs();
    const {id: username} = this.ctx.userInfo;
    args.username = username;
    args.success = null;
    args.oldPassword = args.oldPassword || '';
    args.newPassword = args.newPassword || '';
    args.reNewPassword = args.reNewPassword || '';

    const res = await this._changePwdInternal({checkReNewPassword: true});
    if(!res.ok) {
      const error = errors[res.reason] || 'Change password failed!'
      this.ctx.status = 302;
      this.ctx.redirect('/wolf/rbac/change_pwd?error=' + error);
      return
    }

    args.success = 'change password successfully'
    args.error = null;
    await this.ctx.render('change_pwd.html', args)
  }

  async userInfo() {
    const userInfo = this.ctx.userInfo
    userInfo.appIDs = userInfo.appIDs || []
    const data = {userInfo: util.filterFieldWhite(userInfo, userFields)}
    this.success(data)
  }

}

module.exports = Rbac

