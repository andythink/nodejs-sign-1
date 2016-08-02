
/*
 https://github.com/rzcoder/node-rsa
 http://www.gowhich.com/blog/755
*/

var crypto = require('crypto')

var str1 = crypto.createHash('md5').update('hello md5', 'utf-8').digest('hex')

console.log(str1)

/**
 * @author zhandapeng <896360979@qq.com>
 * @date 7/12/2016
 *
 * openssl pkcs12 -in 9f_KDJZ_private.pfx -out 9f_KDJZ_private.pem -nodes   
 * openssl x509 -in 9fwlc_public.crt -outform der -out 9fwlc_public.der
 * openssl x509 -in 9fwlc_public.crt -inform der -outform pem -out 9fwlc_public.pem
 *
 * 玖富加密解密
 */
'use strict';

const crypto = require('crypto');
const constants = require('constants');
const _padding = constants.RSA_PKCS1_PADDING;
const _encoding = 'base64';
const _signatureAlgorithm = 'RSA-SHA1';


class XxxxRSA {
  constructor(options) {
    this.options = Object.assign({}, options);
  }

  /**
   * 签名
   * @param  {String} data [加密的数据]
   * @return {String}      [签名的数据]
   */
  _sign(data) {
    const sign = crypto.createSign(_signatureAlgorithm);
    sign.update(data, 'utf8');
    return sign.sign(this.options.privateKey, _encoding);
  }

  /**
   * 验签
   * @param  {String} sign [签名数据]
   * @param  {String} data [加密数据]
   * @return {Boolean}      [description]
   */
  _verify(sign, data) {
    const verifier = crypto.createVerify(_signatureAlgorithm);
    verifier.update(new Buffer(data, _encoding), 'utf8');
    return verifier.verify(this.options.publicKey, new Buffer(sign, _encoding));
  }

  /**
   * 加密
   * @param  {String} msg [要加密的数据]
   * @return {Object}     [签名的数据和加密的数据]
   */
  encrypt(msg) {
    const blockSize = 128;
    const padding = 11;

    let buffer = new Buffer(msg);

    const chunkSize = blockSize - padding;
    const nbBlocks = Math.ceil(buffer.length / (chunkSize));

    let outputBuffer = new Buffer(nbBlocks * blockSize);
    for (let i = 0; i < nbBlocks; i++) {
      let currentBlock = buffer.slice(chunkSize * i, chunkSize * (i + 1));
      let encryptedChunk = crypto.publicEncrypt({
        key: this.options.publicKey,
        padding: _padding
      }, currentBlock);

      encryptedChunk.copy(outputBuffer, i * blockSize);
    }

    return {
      data: outputBuffer.toString(_encoding),
      sign: this._sign(outputBuffer)
    };
  };

  /**
   * 解密
   * @param  {Object} obj [签名数据和加密数据]
   * @return {String}     [解密的数据]
   */
  decrypt(obj) {
    if (!this._verify(obj.sign, obj.data)) {
      throw new Error('Sign verify field.');
    }

    const blockSize = 128;
    let buffer = new Buffer(obj.data, _encoding);
    const nbBlocks = Math.ceil(buffer.length / (blockSize));
    let outputBuffer = new Buffer(nbBlocks * blockSize);

    let totalLength = 0;
    for (var i = 0; i < nbBlocks; i++) {
      let currentBlock = buffer.slice(blockSize * i, Math.min(blockSize * (i + 1), buffer.length));
      let decryptedBuf = crypto.privateDecrypt({
        key: this.options.privateKey,
        padding: _padding
      }, currentBlock);

      decryptedBuf.copy(outputBuffer, totalLength);
      totalLength += decryptedBuf.length;
    }

    let data = outputBuffer.slice(0, totalLength);

    return data.toString();
  };
}

export default XxxxRSA;
