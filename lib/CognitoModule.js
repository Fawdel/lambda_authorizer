/* eslint-disable no-useless-constructor */
'use strict';

const logger = require('winston');
const jwt = require('jsonwebtoken');
const request = require('request');
const jwkToPem = require('jwk-to-pem');
let PEMS = null;
class CognitoModule {
  constructor() {

  }
  processAuthRequest(token, tokenIssueer) {
    return new Promise((resolve) => {
      logger.info('executor function within promise is being called to execute async code . . .', {
        context: 'google'
      });
      let decodedJwt = jwt.decode(token, { complete: true });
      if (!decodedJwt) {
        logger.info('Not valid JWT token, returning deny all policy');
        resolve(0);
        return;
      }
      if (decodedJwt.payload['iss' != tokenIssueer]) {
        logger.info('Provided Token not from UserPool, returning deny all policy');
        resolve(0);
        return;
      }
      if (decodedJwt.payload['token_use'] != 'id') {
        console.log('Not an Identity token');
        logger.info('Provided Token is not and identity token, returning deny all policy');
        resolve(0);
        return;
      }
      const kid = decodedJwt.header.kid;
      const pem = PEMS[kid];
      if (!pem) {
        logger.info('Invalid Identity token, returning deny all policy');
        resolve(0);
        return;
      }
      jwt.verify(token, pem, { issuer: tokenIssueer }, function (err, payload) {
        if (err) {
          logger.info('Error while trying to verify the Token, returning deny-all policy');
          resolve(0);
          return;
        } else {
          resolve(decodedJwt.payload['email']);
          return;
        }
      });
    });
  }
  toPem(keyDictionary) {
    var modulus = keyDictionary.n;
    var exponent = keyDictionary.e;
    var key_type = keyDictionary.kty;
    var jwk = { kty: key_type, n: modulus, e: exponent };
    var pem = jwkToPem(jwk);
    return pem;
  }
  callIdProvider(token) {
    let userPoolURI = 'https://cognito-idp.' + 'ap-northeast-1'
    + '.amazonaws.com/' + 'ap-northeast-1_FZ3muOpFG';
    let jwtKeySetURI = userPoolURI + '/.well-known/jwks.json';
    logger.info('Requesting keys from ' + jwtKeySetURI);
    if (!PEMS) {
      request({ url: jwtKeySetURI, json: true },
        (error, response, body) => {
          if (!error && response.statusCode === 200) {
            PEMS = {};
            let keys = body['keys'];
            for (let keyIndex = 0; keyIndex < keys.length; keyIndex++) {
              let kid = keys[keyIndex].kid;
              PEMS[kid] = this.toPem(keys[keyIndex]);
            }
            return this.processAuthRequest(token, userPoolURI);
          } else {
            logger.info('Failed to retrieve the keys from ' +
              'the well known user-pool URI, ');
            logger.info('Error-Code: ', response.statusCode);
            logger.info(error);
            return new Promise(resolve => {
              resolve(0);
            });
          }
        }
      );
    } else {
      return this.processAuthRequest(token, userPoolURI);
    }
  }
}

module.exports = CognitoModule;
