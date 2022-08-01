const config = require('../../conf/config')
const UserModel = require('../model/user')
const {WolfCache} = require('./wolf-cache')
const UserRoleModel = require('../model/user-role')
const RoleModel = require('../model/role')
const log4js = require('./log4js')

const keyPrefix = 'wolfuser'
const userCache = new WolfCache(keyPrefix)


async function getUserInfoFromDbById(uid, appId, isUkey) {
  let userInfo;
  if (isUkey) {
    const where = {ukey: uid}
    userInfo = await UserModel.findOne({where})
  }else{
    userInfo = await UserModel.findByPk(uid)
  }
  if (!userInfo) {
    log4js.error('getUserInfoFromDbById(uid:%d, appId:%d, isUkey:%d) failed! not found', userId, appId, isUkey)
    return null;
  }
  
  userInfo = userInfo.toJSON()
  const userId =  userInfo.id
  const permissions = {}
  userInfo.permissions = permissions;
  userInfo.roles = {}
  if (!appId) {
    return userInfo;
  }

  const where = {appID: appId, userID: userId}
  const options = {where}
  const userRole = await UserRoleModel.findOne(options)
  if (userRole) {
    if (userRole.permIDs) {
      userRole.permIDs.forEach((permId) => {
        permissions[permId] = true;
      })
    }

    if (userRole.roleIDs) {
      for (let i=0; i < userRole.roleIDs.length; i++) {
        const roleId = userRole.roleIDs[i];
        userInfo.roles[roleId] = true;
        const where = {appID: appId, id: roleId}
        const role = await RoleModel.findOne({where})
        if (role) {
          role.permIDs.forEach((permId) => {
            permissions[permId] = true;
          })
        }
      }
    }
  }

  return userInfo;
}

async function getUserInfoByUkey(ukey, appId) {
  const key = `${keyPrefix}:${ukey}-${appId}`
  let userInfo = await userCache.get(key);
  if (userInfo) {
    if (userInfo === '#') {
      userInfo = undefined
    }
    return {userInfo, cached: 'hit'}
  }
  userInfo = await getUserInfoFromDbById(ukey, appId, true)
  if (!userInfo) {
    await userCache.set(key, '#')
    return {}
  }

  await userCache.set(key, userInfo)

  return {userInfo, cached: 'miss'}
}

async function getUserInfoById(userId, appId) {
  const key = `${keyPrefix}:${userId}-${appId}`
  let userInfo = await userCache.get(key);
  if (userInfo) {
    if (userInfo === '#') {
      userInfo = undefined
    }
    return {userInfo, cached: 'hit'}
  }
  userInfo = await getUserInfoFromDbById(userId, appId, false)
  if (!userInfo) {
    await userCache.set(key, '#')
    return {}
  }

  await userCache.set(key, userInfo)

  return {userInfo, cached: 'miss'}
}

async function flushUserCache() {
  await userCache.flushAll();
  log4js.info("---- userCache.flushAll ----")
}

async function flushUserCacheByID(userId, appId){
  const key = `${keyPrefix}:${userId}-${appId}`
  await userCache.del(key)
  log4js.info("---- userCache.del(%s) ----", key)
}

exports.getUserInfoByUkey = getUserInfoByUkey;
exports.getUserInfoById = getUserInfoById;
exports.flushUserCache = flushUserCache;
exports.flushUserCacheByID = flushUserCacheByID;
