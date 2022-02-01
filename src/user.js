const ssha = require('node-ssha256');
const api = require('./util/api');
const encodePassword = require('./util/encodePassword');
const wrapAsync = require('./util/wrapAsync');
const parseLocation = require('./util/parseLocation');

/**
 *  Public user functions
 *  --------------------------
 *  findUser(userName, opts)
 *  addUser(opts)
 *  userExists(userName)
 *  userIsMemberOf(userName, groupName)
 *  authenticateUser(userName, pass)
 *  setUserPassword(userName, pass)
 *  setUserPasswordNeverExpires(userName)
 *  enableUser(userName)
 *  disableUser(userName)
 *  moveUser(userName, location)
 *  getUserLocation(userName)
 *  unlockUser(userName)
 *  removeUser(userName)
 */

module.exports = {
  async getAllUsers(opts) {
    return await this._findByType(opts, ['user']);
  },

  isCorrectEmail(email) {
    if ((!email) || ((email) && (email.trim().length === 0))) {
      return false
    }
    const reg = /^[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,5}$/
    return reg.test(email)
  },

  normalizeLocation(userLocation) {
    if ((!userLocation) || ((userLocation) && (userLocation.trim().length === 0))) {
      return "CN=Users,"
    }
    if (!userLocation.endsWith(',')) {
      userLocation = `${userLocation},`
    }
    return userLocation
  },

  _getRandomIndex(max) {
    return Math.ceil(Math.random() * max)
  },

  _getRandomString(source, length) {
    let result = ""

    for (let i = 0; i < length; i++) {
      let index = this._getRandomIndex(source.length - 1)
      result = `${result}${source[index]}`
    }
    return result
  },

  createPassword() {
    const specials = "!·$%&/()=?¿_-{}*⁺"
    const digits = "0123456789"
    const letters = "qwertyuiopasdfghjklñzxcvbnm"
    const sp = this._getRandomString(specials, 1)
    const dig = this._getRandomString(digits, 3)
    const upp = this._getRandomString(letters, 2).toUpperCase()
    const low = this._getRandomString(letters, 3)
    return `${sp}${dig}${upp}${low}`
  },  

  async addUser(userObject, userLocation) {
    return new Promise(async (resolve, reject) => {
      try {
        if (!this.isCorrectEmail(userObject.mail)) {
          reject(`Incorrect email address: ${userObject.mail}`)
        }
        if ((!userObject.sAMAccountName) || ((userObject.sAMAccountName) && (userObject.sAMAccountName.trim().length === 0))) {
          reject(`sAMAccountName not specified`)
        }
        let password = this.createPassword()
        userObject.userPassword = ssha.create(password)
        userLocation = this.normalizeLocation(userLocation)
        userObject.objectClass = ["top", "person", "organizationalPerson", "user"]//this.config.defaults.userObjectClass
        await this._addObject(`CN=${userObject.sAMAccountName}`, userLocation, userObject)
        await this.setUserPassword(userObject.sAMAccountName, password)
        await this.enableUser(userObject.sAMAccountName)
        resolve({
          userObject,
          password
        })
      }
      catch (err) {
        const ENTRY_EXISTS = String(err.message).indexOf('ENTRY_EXISTS') > -1;
        if (ENTRY_EXISTS) {
          return reject({
            message: `User ${userObject.sAMAccountName} already exists.`,
            httpStatus: 400
          });
        }
        return reject({
          message: `Error creating user: ${err.message}`,
          httpStatus: 503
        });
      }
    })
  },

  async updateUser(userName, opts) {
    return new Promise((resolve, reject) => {
      const domain = this.config.domain;

      const properties = Object.getOwnPropertyNames(opts)
      const operations = []
      for (let i = 0; i < properties.length; i++) {
        const key = properties[i]
        const value = (key === "unicodePwd") ? encodePassword(opts[key]) : opts[key] 
        operations.push({[key]: value})

      }

      let currUserName = userName;
      const go = () => {
        if (operations.length < 1) {
          delete this._cache.users[currUserName];
          delete this._cache.users[userName];
          resolve();
          return;
        }
        let next = operations.pop();
        this.setUserProperty(currUserName, next)
          .then(res => {
            if (next.userPrincipalName !== undefined) {
              currUserName = next.userPrincipalName;
            }
            delete this._cache.users[currUserName];
            go();
          })
          .catch(err => {
            return reject(err);
          });
      };

      this.findUser(currUserName)
        .then(data => {
          if (opts.commonName !== undefined) {
            return this.setUserCN(currUserName, opts.commonName);
          }
        })
        .then(data => {
          let expirationMethod =
            opts.passwordExpires === false
              ? 'setUserPasswordNeverExpires'
              : 'enableUser';
          if (opts.passwordExpires !== undefined) {
            return this[expirationMethod](userName);
          }
        })
        .then(data => {
          let enableMethod =
            opts.enabled === false ? 'disableUser' : 'enableUser';
          if (opts.enabled !== undefined) {
            return this[enableMethod](userName);
          }
        })
        .then(res => {
          go();
        })
        .catch(err => {
          return reject(err);
        });
    });
  },

  async findUser(userName, opts) {
    userName = String(userName || '');
    return new Promise(async (resolve, reject) => {
      let cached = this._cache.get('users', userName);
      if (cached) {
        return resolve(api.processResults(opts, [cached])[0]);
      }
      const domain = this.config.domain;
      userName = userName.indexOf('@') > -1 ? userName.split('@')[0] : userName;
      const filter = `(|(userPrincipalName=${userName}@${domain})(sAMAccountName=${userName}))`;
      const params = {
        filter,
        includeMembership: ['all'],
        includeDeleted: false
      };
      this.ad.find(params, (err, results) => {
        if (err) {
          /* istanbul ignore next */
          return reject(err);
        }
        if (!results || !results.users || results.users.length < 1) {
          this._cache.set('users', userName, {});
          return resolve({});
        }
        this._cache.set('users', userName, results.users[0]);
        results.users = api.processResults(opts, results.users);
        return resolve(results.users[0]);
      });
    });
  },

  async userExists(userName) {
    return new Promise(async (resolve, reject) => {
      const domain = this.config.domain;
      let fullUser = `${userName}@${domain}`;
      this.ad.userExists(fullUser, (error, exists) => {
        if (error) {
          /* istanbul ignore next */
          return reject(error);
        }
        return resolve(exists);
      });
    });
  },

  async userIsMemberOf(userName, groupName) {
    return new Promise(async (resolve, reject) => {
      let userDN;
      this.findUser(userName)
        .then(userObject => {
          userDN = userObject.dn;
          return this._getGroupUsers(groupName);
        })
        .then(users => {
          users = users.filter(u => u.dn === userDN);
          let exists = users.length > 0;
          resolve(exists);
        })
        .catch(err => {
          /* istanbul ignore next */
          reject(err);
        });
    });
  },

  async authenticateUser(userName, pass) {
    const domain = this.config.domain;
    let fullUser = `${userName}@${domain}`;
    return new Promise(async (resolve, reject) => {
      console.log('AUTH USER', fullUser, pass);
      this.ad.authenticate(fullUser, pass, (error, authorized) => {
        let code;
        let out = authorized;
        console.log('BACK FROM AUTH', error, authorized);
        if (error && error.lde_message) {
          out.detail = error.lde_message;
          out.message = String(error.stack).split(':')[0];
          error = undefined;
        }
        if (error) {
          /* istanbul ignore next */
          return reject(error);
        }
        return resolve(out);
      });
    });
  },

  async setUserPassword(userName, pass) {
    return new Promise((resolve, reject) => {
      if (!pass) {
        return reject({ message: 'No password provided.' });
      }
      this._userReplaceOperation(userName, {
        unicodePwd: encodePassword(pass)
      })
        .then(resolve)
        .catch(reject);
    });
  },

  async setUserCN(userName, cn) {
    return new Promise(async (resolve, reject) => {
      this.findUser(userName)
        .then(userObject => {
          let oldDN = userObject.dn;
          let parts = String(oldDN).split(',');
          parts.shift();
          parts.unshift(`CN=${cn}`);
          return this._modifyDN(oldDN, parts.join(','));
        })
        .then(result => {
          delete this._cache.users[userName];
          resolve(result);
        })
        .catch(err => {
          /* istanbul ignore next */
          reject(err);
        });
    });
  },

  async setUserProperty(userName, obj) {
    return this._userReplaceOperation(userName, obj);
  },

  async setUserPasswordNeverExpires(userName) {
    const NEVER_EXPIRES = 66048;
    return this._userReplaceOperation(userName, {
      userAccountControl: NEVER_EXPIRES
    });
  },

  async enableUser(userName) {
    const ENABLED = 512;
    return this._userReplaceOperation(userName, {
      userAccountControl: ENABLED
    });
  },

  async disableUser(userName) {
    const DISABLED = 514;
    return this._userReplaceOperation(userName, {
      userAccountControl: DISABLED
    });
  },

  async moveUser(userName, location) {
    return new Promise(async (resolve, reject) => {
      location = parseLocation(location);
      this.findUser(userName)
        .then(userObject => {
          let oldDN = userObject.dn;
          let baseDN = String(this.config.baseDN).replace(/dc=/g, 'DC=');
          let newDN = `CN=${userObject.cn},${location}${baseDN}`;
          return this._modifyDN(oldDN, newDN);
        })
        .then(result => {
          delete this._cache.users[userName];
          resolve(result);
        })
        .catch(err => {
          /* istanbul ignore next */
          reject(err);
        });
    });
  },

  async getUserLocation(userName) {
    return new Promise(async (resolve, reject) => {
      this.findUser(userName)
        .then(userObject => {
          if (Object.keys(userObject).length < 1) {
            /* istanbul ignore next */
            return reject({ error: true, message: 'User does not exist.' });
          }
          let dn = userObject.dn;
          let left = String(dn)
            .replace(/DC=/g, 'dc=')
            .replace(/CN=/g, 'cn=')
            .replace(/OU=/g, 'ou=')
            .split(',dc=')[0];
          let location = String(left)
            .split(',')
            .slice(1)
            .reverse()
            .join('/')
            .replace(/cn=/g, '!')
            .replace(/ou=/g, '');
          return resolve(location);
        })
        .catch(err => {
          /* istanbul ignore next */
          return reject(err);
        });
    });
  },

  async unlockUser(userName) {
    return this._userReplaceOperation(userName, {
      lockoutTime: 0
    });
  },

  async removeUser(userName) {
    return new Promise(async (resolve, reject) => {
      this.findUser(userName).then(userObject => {
        if (Object.keys(userObject).length < 1) {
          return reject({ error: true, message: 'User does not exist.' });
        }
        this._deleteObjectByDN(userObject.dn)
          .then(resp => {
            resolve(resp);
          })
          .catch(err => {
            /* istanbul ignore next */
            reject(Object.assign(err, { error: true }));
          });
      });
    });
  }
};
