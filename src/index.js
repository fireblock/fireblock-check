import axios from 'axios'
import { keccak256 } from 'js-sha3'
import "core-js/shim"; // included < Stage 4 proposals
import "regenerator-runtime/runtime";

// error -> message
class FError {

  constructor (message, description) {
    this.name = 'FError'
    this.message = message
    this.description = description
  }

  getType () {
    return this.message
  }

  toString () {
    return this.message + ' ' + this.description
  }
}

const INVALID_AUTHENTITICATION = 'invalid authentication'
const INVALID_PARAMETERS = 'invalid parameters'
const NETWORK_ERROR = 'network error'
const UNKNOWN_ERROR = 'unknown error'
const UNKNOWN_ELEMENT = 'unknown element'
const HACK_DETECTED = 'hack detected'
const INVALID_CARD = 'invalid card'
const INVALID_PRIV_KEY = 'invalid priv key'
const INVALID_SIGNATURE = 'invalid signature'
const ALREADY_EXISTS = 'already exists'
const REGISTER_ERROR = 'register error'
const PGP_CREATE_ERROR = 'pgp create error'
const ERROR_SITE_HACKED = 'Critical ERROR: this is not the real website!'

const ECDSA_PREFIX = '0x200000000000000000000000'

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []
  var i = 0

  for (; i < length; i++) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (leadSurrogate) {
        // 2 leads in a row
        if (codePoint < 0xDC00) {
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          leadSurrogate = codePoint
          continue
        } else {
          // valid surrogate pair
          codePoint = leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00 | 0x10000
          leadSurrogate = null
        }
      } else {
        // no lead yet

        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else {
          // valid lead
          leadSurrogate = codePoint
          continue
        }
      }
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
      leadSurrogate = null
    }

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x200000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return new Uint8Array(bytes)
}


/**
 * compute a keccak256 as ethereum
 * @param {string} str
 * @returns sha3 
 */
function sha3 (str) {
  return '0x' + keccak256(str)
}

/**
 * compute a sha2 256
 * @param {String} str
 * @returns sha2_256
 */
async function sha256 (str) {
  let data = utf8ToBytes(str)
  let r = await window.crypto.subtle.digest({name: 'SHA-256'}, data)
  let digestView = new Uint8Array(r)
  let hash = ''
  let length = digestView.byteLength
  for (var i = 0; i < length; i++) {
    let hex = Number(digestView[i]).toString('16')
    if (hex.length === 1) { hex = '0' + hex }
    hash += hex
  }
  return '0x' + hash
}

/**
 * compute a sha1 160
 * @param {String} str
 */
async function sha1 (str) {
  let data = utf8ToBytes(str)
  let r = await window.crypto.subtle.digest({name: 'SHA-1'}, data)
  let digestView = new Uint8Array(r)
  let hash = ''
  let length = digestView.byteLength
  for (var i = 0; i < length; i++) {
    let hex = Number(digestView[i]).toString('16')
    if (hex.length === 1) { hex = '0' + hex }
    hash += hex
  }
  return '0x' + hash
}

/**
 * ecdsa fingerprint into bytes32
 * @param {string} ecdsa
 * @returns bytes32 
 */
function ecdsaToB32 (ecdsa) {
  if (ecdsa.indexOf('0x') === 0) {
    return ECDSA_PREFIX + ecdsa.substring(2)
  }
  return ECDSA_PREFIX + ecdsa
}

/**
 * compute the fingerprint of an ecdsa key (JSON input)
 * @param {json} key
 * @returns fp
 */
async function getFingerprint (key) {
  let crv = key.crv
  let kty = key.kty
  let x = key.x
  let y = key.y
  let fpData = `{"crv":"${crv}","kty":"${kty}","x":"${x}","y":"${y}"}`
  let k = await sha1(fpData)
  return k
}

/**
 * load an ECDSA public key (string input)
 * @param {string} pubkey
 * @returns object {key, fingerprint, pubkey}
 */
async function loadPublicKey (pubkey) {
  let jpubkey = JSON.parse(pubkey)
  let key = await window.crypto.subtle.importKey('jwk', jpubkey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  let fingerprint = await getFingerprint(jpubkey)
  let keyuid = ecdsaToB32(fingerprint)
  return { key, keyuid, fingerprint, txt: pubkey }
}

/**
 * verify an ecdsa signature
 * @param {key} pubkeyObj 
 * @param {string} msg 
 * @param {string} signature
 * @returns {bool} true if signature is checked
 */
async function verify (pubkeyObj, msg, signature) {
  let data = utf8ToBytes(msg)
  let sig = Buffer.from(signature, 'base64')
  let res = await window.crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, pubkeyObj, sig, data)
  return res
}

function _parseCard (card) {
  try {
    return JSON.parse(card)
  } catch (err) {
    // return null if not valid json text
    return null
  }
}

function _getCardElement (jCard, provider) {
  for (let cardElement of jCard) {
    if (cardElement.provider === provider) {
      return cardElement
    }
  }
  return null
}


/**
 * check the card
 * @param {string} card txt
 * @returns false or { useruid, fingerprint, keyuid }
 */
async function checkCard (card) {
  let jCard = _parseCard(card)
  // check if invalid json or not an array
  if (!Array.isArray(jCard)) {
    return false
  }
  let useruidCE = _getCardElement(jCard, 'fireblock')
  if (!useruidCE) {
    return false
  }
  // get useruid
  let useruid = useruidCE.uid
  if ((!useruid) || ((typeof useruid) !== 'string')) {
    return false
  }
  // check length of useruid
  if ((useruid.length < 4) || (useruid.length > 12)) {
    return false
  }
  // useruid seems valid
  // check if we have a key (pgp or ecdsa or eth)
  let pgpCE = _getCardElement(jCard, 'pgp')
  let ecdsaCE = _getCardElement(jCard, 'ecdsa')
  let ethCE = _getCardElement(jCard, 'eth')
  let count = 0
  if (pgpCE) { count += 1 }
  if (ecdsaCE) { count += 1 }
  if (ethCE) { count += 1 }
  if (count !== 1) {
    return false
  }
  let fingerprint
  let keyuid
  // pgp case
  if (pgpCE) {
    console.log('PGP key not supported')
    return false
  }
  // ecdsa case
  if (ecdsaCE) {
    fingerprint = ecdsaCE.uid
    keyuid = ecdsaToB32(ecdsaCE.uid)
  }
  // eth case
  if (ethCE) {
    fingerprint = ecdsaCE.uid
    keyuid = ecdsaCE.uid
  }
  if ((!keyuid) || ((typeof keyuid) !== 'string')) {
    return false
  }
  if (keyuid.length !== 66) {
    return false
  }
  // get pgp key public
  try {
    return { useruid, fingerprint, keyuid }
  } catch (err) {
    return false
  }
}

async function checkPublicKey (pubkey) {
  let key = await loadPublicKey(pubkey)
  return key
}

async function userVerify (hash, useruuid) {
  let response
  try {
    response = await HTTP.post('/api/verify-by-user', { hash, useruuid })
  } catch (err) {
    throw new FError(NETWORK_ERROR, 'verify')
  }
  if (response.data && response.data.data) {
    // object with verified, signature and eth
    let result = response.data.data
    if (result.id !== 'success') {
      console.error('userVerify failed', response)
      throw new FError(UNKNOWN_ERROR, 'verify error')
    }
    if (result.value.length === 0) {
      console.error('userVerify no result', response)
      throw new FError(UNKNOWN_ERROR, 'verify error')
    }
    // DEBUG console.log('userVerify success', result.value)
    return result.value
  } else {
    console.error('userVerify error', response)
    throw new FError(UNKNOWN_ERROR, 'verify error')
  }
}

async function checkJSFile (url, text, name, useruid) {
  let regexText = '(' + name + '\\.[0-9A-Fa-f]*\\.js)'
  let regex = new RegExp(regexText, 'g')
  let m1 = text.match(regex);
  if (m1 === null) {
    console.log(ERROR_SITE_HACKED + ' ERR100', name)
    return false
  }
  let jsfile = ''
  if (typeof m1 === 'object' && Array.isArray(m1)) {
    jsfile = m1[0]
  } else {
    jsfile = m1
  }
  let appjs = url + '/js/' + jsfile
  let response = await HTTP.get(appjs)
  let js1 = response.data
  let r = await checkUrlContent (appjs, js1, useruid)
  console.log(`name: ${name} ${r}`)
  return r
}

async function checkUrlContent (url, text, useruid) {
  let hash = await sha256(text)
  console.log('userVerify', url, hash, useruid)
  let results = await userVerify(hash, useruid)
  if (results.length === 0) {
    console.error(ERROR_SITE_HACKED + ' ERR001')
    return false
  }
  for (let result of results) {
    // DEBUG: console.log('result', result)
    // look results

    // load keys
    let key = await loadPublicKey(result.key.pubkey)
    if (key.keyuid !== result.key.keyuid) {
      console.error(ERROR_SITE_HACKED + ' ERR006')
      continue
    }
    let pkey = await loadPublicKey(result.pkey.pubkey)
    if (pkey.keyuid !== result.pkey.keyuid) {
      console.error(ERROR_SITE_HACKED + ' ERR007')
      continue
    }

    // check signatures
    // certificate signature
    let certificateMsg = `${hash}||${key.keyuid}`
    let ckCertifcateSignature = await verify(key.key, certificateMsg, result.certificate.signature)
    // DEBUG console.log(`ckCertifcateSignature`, ckCertifcateSignature)
    // metadata signature
    let ckMetadataSignature = true
    if (result.certificate.metadataSignature) {
      let metadataSID = sha3(result.certificate.metadata)
      let metadataMsg = `${metadataSID}||${hash}||${key.keyuid}`
      ckMetadataSignature = await verify(key.key, metadataMsg, result.certificate.metadataSignature)
      // DEBUG console.log(`ckMetadataSignature`, ckMetadataSignature)
    }
    // delegation signature
    let delegationMsg = `approved key is ${key.keyuid} at ${result.key.date}`
    let ckDelegationSignature = await verify(pkey.key, delegationMsg, result.key.signature)
    // DEBUG console.log(`ckDelegationSignature`, ckDelegationSignature)
    // card signature
    let cardUID = sha3(result.card.txt)
    let cardMsg = `register card ${cardUID} at ${result.card.date}`
    let ckCardSignature = await verify(pkey.key, cardMsg, result.card.signature)
    // DEBUG console.log(`ckCardSignature`, ckCardSignature)
    if ((!ckCertifcateSignature) || (!ckMetadataSignature) || (!ckDelegationSignature) || (!ckCardSignature)) {
      console.error(ERROR_SITE_HACKED + ' ERR003')
      continue
    }

    // card checking
    if (cardUID !== result.card.uid) {
      console.error(ERROR_SITE_HACKED + ' ERR002')
      continue
    }
    let res = await checkCard(result.card.txt)
    if (!res) {
      console.error(ERROR_SITE_HACKED + ' ERR002')
      continue
    }
    if (res.useruid !== useruid) {
      console.error(ERROR_SITE_HACKED + ' ERR002')
      continue
    }
    if (res.keyuid !== pkey.keyuid) {
      console.error(ERROR_SITE_HACKED + ' ERR002')
      continue
    }
    console.log(`${url}: card checked & signatures checked`)
    return true
  }
  return false
}

let HTTP

async function main (url, useruid) {
  if (/Edge/.test(navigator.userAgent)) {
    let head = document.getElementsByTagName('head')[0]
    let script = document.createElement('script')
    script.type = 'text/javascript'
    script.src = 'https://fireblock.io/static/js/webcrypto-liner.min.js'
    head.appendChild(script)
    let script2 = document.createElement('script')
    script2.type = 'text/javascript'
    script2.src = 'https://fireblock.io/static/js/asmcrypto.js'
    head.appendChild(script2)
    let script3 = document.createElement('script')
    script3.type = 'text/javascript'
    script3.src = 'https://fireblock.io/static/js/elliptic.js'
    head.appendChild(script3)
  }
  HTTP = axios.create({ baseURL: url })
  try {
    // read index.html content
    let response = await HTTP.get(url)
    let text = response.data
    // do in //
    let p0 = checkUrlContent (url, text, useruid)
    let p1 = checkJSFile(url, text, 'app', useruid)
    let p2 = checkJSFile(url, text, 'chunk-vendors', useruid)

    await Promise.all([p0, p1, p2])
    if (p0 && p1 && p2) {
      console.log('SUCCESS')
      return 'verified'
    }
    console.error('FAILED')
    return 'invalid'
  } catch (err) {
    console.error('FAILED', err)
    return 'not verified'
  }
}

window.checkFireblock = main
