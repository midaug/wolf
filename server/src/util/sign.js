const crypto = require('crypto')

function md5hex(data) {
  const md5 = crypto.createHash('md5')
  return md5.update(data).digest('hex')
}

function encrypt(ukey, usecret, args){
  const keys = []
  const params = []
  for (const key in args) {
    keys.push(key)
  }
  keys.sort()
  for (const i in keys) {
    params.push(keys[i] + "=" + args[keys[i]])
  }
  const sstr = params.join("&")
  return md5hex(ukey + sstr + usecret)
}

exports.encrypt = encrypt
