const config = require('../../conf/config')
const log4js = require('log4js');
const objConfig = require('../../conf/log4js.json')
objConfig.categories.default.level=config.logLevel
log4js.configure(objConfig);
module.exports = log4js.getLogger('server')